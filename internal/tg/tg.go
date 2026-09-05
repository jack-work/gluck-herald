// Package tg is a minimal Telegram Bot API client: long polling in,
// markdown-rendered messages out. Stdlib only: the Bot API is two calls and
// long polling is a query parameter, so a framework would be all cost.
package tg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jack-work/gluck-herald/internal/md"
)

const (
	defaultAPIBase = "https://api.telegram.org/bot"

	// PollTimeout is the long-poll window offered to Telegram. This is
	// spain's own outbound call and does not traverse the tunnel, so it is
	// unconstrained by Cloudflare's ~100s ceiling.
	PollTimeout = 30 * time.Second

	// MaxMsgRunes keeps a message under Telegram's 4096 limit with room for
	// the HTML tags the renderer adds.
	MaxMsgRunes = 3800
)

type Client struct {
	token string
	base  string
	http  *http.Client
}

// New builds a client for the real Telegram API.
//
// HERALD_TELEGRAM_BASE redirects it elsewhere, which exists so the end-to-end
// tests can drive a fake API. It is read from the environment rather than
// taken as a parameter so that no production code path can be handed a
// different endpoint by accident.
func New(token string) *Client {
	base := defaultAPIBase
	if b := strings.TrimSpace(os.Getenv("HERALD_TELEGRAM_BASE")); b != "" {
		base = strings.TrimRight(b, "/") + "/bot"
	}
	return &Client{
		token: token,
		base:  base,
		http:  &http.Client{Timeout: PollTimeout + 60*time.Second},
	}
}

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
	ErrorCode   int             `json:"error_code"`
}

// Error is a Telegram-side rejection, carrying the code so callers can
// distinguish the ones that matter: notably 409 Conflict, which means a
// second getUpdates consumer is running and updates are being split.
type Error struct {
	Method string
	Code   int
	Desc   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("telegram %s: %d %s", e.Method, e.Code, e.Desc)
}

// IsConflict reports the 409 that Telegram returns when another process is
// already polling getUpdates for this bot.
func IsConflict(err error) bool {
	var e *Error
	if ok := asError(err, &e); ok {
		return e.Code == http.StatusConflict
	}
	return false
}

func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (c *Client) call(ctx context.Context, method string, params url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+c.token+"/"+method, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	var r apiResponse
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		return fmt.Errorf("%s: bad json (http %d): %w", method, resp.StatusCode, err)
	}
	if !r.OK {
		return &Error{Method: method, Code: r.ErrorCode, Desc: r.Description}
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// Me returns the bot's own username, and doubles as a token check at startup.
func (c *Client) Me(ctx context.Context) (string, error) {
	var me struct {
		Username string `json:"username"`
	}
	if err := c.call(ctx, "getMe", url.Values{}, &me); err != nil {
		return "", err
	}
	return me.Username, nil
}

type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message"`
}

// PhotoSize is one rendition of a photo. Telegram sends an array of them,
// smallest first, and they are the same image at different scales.
type PhotoSize struct {
	FileID       string `json:"file_id"`
	FileUniqueID string `json:"file_unique_id"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	FileSize     int64  `json:"file_size"`
}

// Document is a file sent as an attachment rather than as a photo. A
// screenshot sent with "send as file" arrives here and not in Photo, which is
// why both paths exist.
type Document struct {
	FileID       string `json:"file_id"`
	FileUniqueID string `json:"file_unique_id"`
	FileName     string `json:"file_name"`
	MimeType     string `json:"mime_type"`
	FileSize     int64  `json:"file_size"`
}

type Message struct {
	MessageID int64       `json:"message_id"`
	Text      string      `json:"text"`
	Caption   string      `json:"caption"`
	Photo     []PhotoSize `json:"photo"`
	Document  *Document   `json:"document"`
	Date      int64       `json:"date"`
	Chat      struct {
		ID       int64  `json:"id"`
		Type     string `json:"type"`
		Username string `json:"username"`
	} `json:"chat"`
	From struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
	} `json:"from"`
}

// Body returns the message text, falling back to a media caption.
func (m *Message) Body() string {
	if t := strings.TrimSpace(m.Text); t != "" {
		return t
	}
	return strings.TrimSpace(m.Caption)
}

// Attachment is one downloadable thing hanging off a message, flattened so
// callers do not care whether it arrived as a photo or as a document.
type Attachment struct {
	FileID       string
	FileUniqueID string
	Kind         string // "photo" or "document"
	Name         string // suggested filename, may be empty
	MimeType     string
	Width        int
	Height       int
	Size         int64
}

// Attachments returns what the message carries, largest photo rendition only.
//
// Telegram's photo array is one image at several scales; downloading every
// size would spend the disk and the round trips to store the same picture
// four times. The largest is the one worth keeping: an aria reading a
// screenshot needs the pixels the text was rendered at.
func (m *Message) Attachments() []Attachment {
	var out []Attachment
	if len(m.Photo) > 0 {
		best := m.Photo[0]
		for _, p := range m.Photo {
			if p.Width*p.Height > best.Width*best.Height {
				best = p
			}
		}
		out = append(out, Attachment{
			FileID: best.FileID, FileUniqueID: best.FileUniqueID,
			Kind: "photo", Name: "photo.jpg", MimeType: "image/jpeg",
			Width: best.Width, Height: best.Height, Size: best.FileSize,
		})
	}
	if m.Document != nil && m.Document.FileID != "" {
		out = append(out, Attachment{
			FileID: m.Document.FileID, FileUniqueID: m.Document.FileUniqueID,
			Kind: "document", Name: m.Document.FileName,
			MimeType: m.Document.MimeType, Size: m.Document.FileSize,
		})
	}
	return out
}

// GetUpdates long-polls for messages newer than offset.
func (c *Client) GetUpdates(ctx context.Context, offset int64) ([]Update, error) {
	v := url.Values{}
	v.Set("offset", strconv.FormatInt(offset, 10))
	v.Set("timeout", strconv.Itoa(int(PollTimeout/time.Second)))
	v.Set("allowed_updates", `["message"]`)

	cctx, cancel := context.WithTimeout(ctx, PollTimeout+30*time.Second)
	defer cancel()

	var ups []Update
	if err := c.call(cctx, "getUpdates", v, &ups); err != nil {
		return nil, err
	}
	return ups, nil
}

// Send renders markdown to Telegram HTML and delivers it, chunked.
//
// HTML is the pragmatic parse_mode: only & < > need escaping, where
// MarkdownV2 demands 18 characters and drops the entire message on a single
// miss. If Telegram still rejects the markup, the chunk is resent as plain
// text: a formatting mistake must never eat a message.
func (c *Client) Send(ctx context.Context, chat int64, markdown string) error {
	for _, part := range Chunk(markdown, MaxMsgRunes) {
		html := md.ToHTML(part)
		err := c.sendOne(ctx, chat, html, true)
		if err != nil && strings.Contains(err.Error(), "can't parse") {
			err = c.sendOne(ctx, chat, md.StripTags(html), false)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) sendOne(ctx context.Context, chat int64, text string, html bool) error {
	v := url.Values{}
	v.Set("chat_id", strconv.FormatInt(chat, 10))
	v.Set("text", text)
	v.Set("link_preview_options", `{"is_disabled":true}`)
	if html {
		v.Set("parse_mode", "HTML")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.call(cctx, "sendMessage", v, nil)
}

// Typing shows the "typing…" indicator; it lapses after a few seconds.
func (c *Client) Typing(ctx context.Context, chat int64) error {
	v := url.Values{}
	v.Set("chat_id", strconv.FormatInt(chat, 10))
	v.Set("action", "typing")
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.call(cctx, "sendChatAction", v, nil)
}

// Chunk splits text on rune boundaries, preferring newlines near the limit.
func Chunk(s string, limit int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{"(empty message)"}
	}
	var out []string
	r := []rune(s)
	for len(r) > limit {
		cut := limit
		if i := strings.LastIndex(string(r[:limit]), "\n"); i > limit/2 {
			cut = len([]rune(string(r[:limit])[:i]))
		}
		out = append(out, strings.TrimRight(string(r[:cut]), "\n"))
		r = r[cut:]
	}
	if rest := strings.TrimSpace(string(r)); rest != "" {
		out = append(out, rest)
	}
	return out
}

// MaxDownload bounds what one attachment may write to disk.
//
// Telegram caps bot downloads near 20MB, but the ceiling is ours to enforce
// rather than theirs to promise: a lying Content-Length must not be able to
// fill the disk of the machine that is also the house router.
const MaxDownload = 25 << 20

// fileBase is the download host, which is a different path from the API.
// Telegram serves calls at /bot<token>/<method> and file bytes at
// /file/bot<token>/<file_path>.
func (c *Client) fileBase() string {
	return strings.TrimSuffix(c.base, "bot") + "file/bot"
}

// Download resolves a file_id and writes the bytes to w, returning the count
// and the file_path Telegram reported (whose extension is the only honest
// hint about the format).
//
// Two calls, because the Bot API offers no single one: getFile mints a
// short-lived path, then the bytes come from the file host.
func (c *Client) Download(ctx context.Context, fileID string, w io.Writer) (int64, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var meta struct {
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
	}
	if err := c.call(ctx, "getFile", url.Values{"file_id": {fileID}}, &meta); err != nil {
		return 0, "", err
	}
	if meta.FilePath == "" {
		return 0, "", fmt.Errorf("getFile: telegram returned no file_path")
	}
	if meta.FileSize > MaxDownload {
		return 0, "", fmt.Errorf("file is %d bytes, over the %d limit", meta.FileSize, MaxDownload)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.fileBase()+c.token+"/"+meta.FilePath, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("download: http %d", resp.StatusCode)
	}

	// LimitReader at the cap plus one: reading one byte past it is how an
	// oversized body is detected without trusting the header that declared it.
	n, err := io.Copy(w, io.LimitReader(resp.Body, MaxDownload+1))
	if err != nil {
		return n, meta.FilePath, err
	}
	if n > MaxDownload {
		return n, meta.FilePath, fmt.Errorf("file exceeded %d bytes", MaxDownload)
	}
	return n, meta.FilePath, nil
}
