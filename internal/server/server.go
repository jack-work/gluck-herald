// Package server is herald's HTTP API and its Telegram poller.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jack-work/gluck-herald/internal/auth"
	"github.com/jack-work/gluck-herald/internal/store"
	"github.com/jack-work/gluck-herald/internal/tg"
)

// MaxWait bounds a long poll.
//
// Cloudflare terminates a held request at about 100 seconds and returns 524,
// so /v1/inbox must answer well before that. 60s leaves margin for the
// tunnel and for a slow client, and the client simply re-polls.
const MaxWait = 60 * time.Second

type Config struct {
	Addr     string
	Bot      *tg.Client
	Store    *store.Store
	Verifier *auth.Verifier

	// RequiredGroup, when set, gates every authenticated route. Coarse
	// authorization by lldap group; finer scopes are per-route below.
	RequiredGroup string

	// AllowedChats restricts which Telegram chats may be addressed. Empty
	// means any — acceptable only because the bot has a single known peer.
	AllowedChats map[int64]bool
}

type Server struct {
	cfg Config
	mux *http.ServeMux

	// verify is the token check, swappable so tests can exercise routing
	// and authorization without re-testing the crypto that auth's own
	// tests cover.
	verify func(context.Context, string) (*auth.Identity, error)
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	if cfg.Verifier != nil {
		s.verify = cfg.Verifier.Verify
	}
	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("POST /v1/say", s.authed(s.say))
	s.mux.HandleFunc("GET /v1/inbox", s.authed(s.inbox))
	s.mux.HandleFunc("POST /v1/inbox/ack", s.authed(s.ack))
	s.mux.HandleFunc("GET /v1/whoami", s.authed(s.whoami))
	return s
}

func (s *Server) Handler() http.Handler { return logging(s.mux) }

// ---------- middleware ----------

type ctxKey int

const identityKey ctxKey = 0

// authed verifies the bearer token and enforces the coarse group gate.
//
// Herald checks the token itself rather than trusting an upstream header:
// on the bearer path Caddy passes the request through untouched, so nothing
// before this point has validated anything.
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.verify(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			if errors.Is(err, auth.ErrNoToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="herald"`)
			}
			log.Printf("auth refused from %s: %v", r.RemoteAddr, err)
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if g := s.cfg.RequiredGroup; g != "" && !id.HasGroup(g) {
			log.Printf("auth: %s lacks group %s", id.Username, g)
			writeErr(w, http.StatusForbidden, "missing group "+g)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
	}
}

func identityOf(r *http.Request) *auth.Identity {
	if id, ok := r.Context().Value(identityKey).(*auth.Identity); ok {
		return id
	}
	return &auth.Identity{}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		// Every credentialed action is logged. With agents you cannot
		// prevent misuse, only notice it quickly.
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ---------- routes ----------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	offset, pending := s.cfg.Store.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "offset": offset, "pending": pending,
	})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": id.Subject, "username": id.Username,
		"groups": id.Groups, "scopes": id.Scopes,
	})
}

type sayRequest struct {
	Chat int64  `json:"chat"`
	Text string `json:"text"`
}

func (s *Server) say(w http.ResponseWriter, r *http.Request) {
	var req sayRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeErr(w, http.StatusBadRequest, "text is empty")
		return
	}
	if req.Chat == 0 {
		writeErr(w, http.StatusBadRequest, "chat is required")
		return
	}
	// The caller names a chat, but only from a fixed set. A gateway whose
	// caller may name any destination is an open relay that signs its own
	// requests — the lesson IMDS taught expensively.
	if len(s.cfg.AllowedChats) > 0 && !s.cfg.AllowedChats[req.Chat] {
		writeErr(w, http.StatusForbidden, "chat not permitted")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.cfg.Bot.Send(ctx, req.Chat, req.Text); err != nil {
		log.Printf("say by %s to %d failed: %v", identityOf(r).Username, req.Chat, err)
		writeErr(w, http.StatusBadGateway, "telegram: "+err.Error())
		return
	}
	log.Printf("say by %s to chat %d (%d bytes)", identityOf(r).Username, req.Chat, len(req.Text))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// inbox long-polls for messages newer than ?after=, returning 204 when the
// wait elapses with nothing to report.
func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	wait := 25 * time.Second
	if d, err := time.ParseDuration(r.URL.Query().Get("wait")); err == nil && d >= 0 {
		wait = d
	}
	if wait > MaxWait {
		wait = MaxWait
	}

	if msgs := s.cfg.Store.Peek(after, limit); len(msgs) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
		return
	}
	if wait == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Register for the wake *before* re-checking, so a message arriving in
	// between is not missed.
	woken := s.cfg.Store.Wait()
	if msgs := s.cfg.Store.Peek(after, limit); len(msgs) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
		return
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-woken:
		writeJSON(w, http.StatusOK, map[string]any{"messages": s.cfg.Store.Peek(after, limit)})
	case <-timer.C:
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Through int64 `json:"through"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if err := s.cfg.Store.Ack(req.Through); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// ---------- telegram poller ----------

// Poll runs the Telegram long-poll loop until ctx is done.
//
// Telegram permits exactly one getUpdates consumer per bot: a second caller
// receives 409 Conflict and the two silently split the message stream. That
// is a configuration error, not a transient one, so it is logged loudly
// rather than retried quietly.
func Poll(ctx context.Context, bot *tg.Client, st *store.Store, allowed map[int64]bool) {
	backoff := time.Second
	for ctx.Err() == nil {
		ups, err := bot.GetUpdates(ctx, st.Offset())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if tg.IsConflict(err) {
				log.Printf("CONFLICT: another process is polling this bot — "+
					"messages are being split between us. Stop the other one. (%v)", err)
			} else {
				log.Printf("getUpdates: %v (retry in %s)", err, backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second

		var msgs []store.Message
		var offset = st.Offset()
		for _, u := range ups {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			m := u.Message
			if m == nil || m.Body() == "" {
				continue
			}
			if len(allowed) > 0 && !allowed[m.Chat.ID] {
				log.Printf("REFUSED chat=%d user=%d (@%s)", m.Chat.ID, m.From.ID, m.From.Username)
				_ = bot.Send(ctx, m.Chat.ID, fmt.Sprintf("not authorized.\nchat id: %d", m.Chat.ID))
				continue
			}
			msgs = append(msgs, store.Message{
				ID:       u.UpdateID,
				Chat:     m.Chat.ID,
				From:     m.From.Username,
				Text:     m.Body(),
				Received: time.Unix(m.Date, 0).UTC(),
			})
		}
		if len(ups) == 0 {
			continue
		}
		// Persist offset and messages together, before anyone is told.
		if err := st.Append(offset, msgs); err != nil {
			log.Printf("persist: %v — not advancing offset", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, m := range msgs {
			log.Printf("inbox += chat=%d (@%s) %d bytes", m.Chat, m.From, len(m.Text))
		}
	}
}
