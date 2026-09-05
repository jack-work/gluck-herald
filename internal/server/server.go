// Package server is herald's HTTP API and its Telegram poller.
//
// Herald is deliberately boring: it is the Telegram Bot API with names
// instead of chat ids, an inbox that survives restarts, and per-client
// authorization. It knows nothing about figaro, calendars, or anything else
// that might want to send a message: those are its callers, and they stay
// its callers.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	gauthz "github.com/jack-work/gluck-authz"
	"github.com/jack-work/gluck-herald/internal/authz"
	"github.com/jack-work/gluck-herald/internal/route"
	"github.com/jack-work/gluck-herald/internal/store"
	"github.com/jack-work/gluck-herald/internal/tg"
)

// MaxWait bounds a long poll.
//
// Cloudflare terminates a held request at about 100 seconds and returns 524,
// so /v1/inbox must answer well before that. 60s leaves margin for the
// tunnel and a slow client, and the client simply re-polls.
const MaxWait = 60 * time.Second

type Config struct {
	Bot      *tg.Client
	Store    *store.Store
	Verifier *gauthz.Verifier
	Policy   *authz.Policy
	Routes   *route.Table
}

type Server struct {
	cfg Config
	mux *http.ServeMux

	// verify and send are swappable so tests can exercise routing and
	// authorization without re-testing the crypto that auth's own tests
	// cover, and without a live Telegram.
	verify   func(context.Context, string) (*gauthz.Identity, error)
	send     func(context.Context, int64, string) error
	typingFn func(context.Context, int64) error
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	if cfg.Verifier != nil {
		s.verify = cfg.Verifier.Verify
	}
	if cfg.Bot != nil {
		s.send = cfg.Bot.Send
		s.typingFn = cfg.Bot.Typing
		s.typingFn = cfg.Bot.Typing
	}
	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("GET /v1/whoami", s.need(authz.RoleAdmin, s.whoami))
	s.mux.HandleFunc("GET /v1/routes", s.need(authz.RoleSay, s.routes))
	s.mux.HandleFunc("POST /v1/say", s.need(authz.RoleSay, s.say))
	s.mux.HandleFunc("POST /v1/typing", s.need(authz.RoleSay, s.typing))
	s.mux.HandleFunc("GET /v1/inbox", s.need(authz.RoleInbox, s.inbox))
	s.mux.HandleFunc("POST /v1/inbox/ack", s.need(authz.RoleInbox, s.ack))
	return s
}

func (s *Server) Handler() http.Handler { return logging(s.mux) }

// ---------- middleware ----------

type ctxKey int

const identityKey ctxKey = 0

// need verifies the bearer token and requires a role.
//
// Herald checks the token itself rather than trusting an upstream header: on
// the bearer path Caddy passes the request through untouched, so nothing
// before this point has validated anything.
func (s *Server) need(role authz.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.verify(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			if errors.Is(err, gauthz.ErrNoToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="herald"`)
			}
			log.Printf("auth refused from %s: %v", r.RemoteAddr, err)
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// A client herald has never heard of is a 401: the fix is
		// registration. A known client lacking a role is a 403: the fix is
		// policy. Different problems, different answers.
		if !s.cfg.Policy.Known(id.ClientID) {
			log.Printf("auth: client %q is not in the policy", id.ClientID)
			writeErr(w, http.StatusUnauthorized, "client not registered with herald")
			return
		}
		if !s.cfg.Policy.Allows(id.ClientID, role) {
			log.Printf("authz: client %q lacks role %q (has: %v)",
				id.ClientID, role, s.cfg.Policy.Roles(id.ClientID))
			writeErr(w, http.StatusForbidden, "client lacks role "+string(role))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
	}
}

func identityOf(r *http.Request) *gauthz.Identity {
	if id, ok := r.Context().Value(identityKey).(*gauthz.Identity); ok {
		return id
	}
	return &gauthz.Identity{}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "offset": offset, "pending": pending})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": id.Subject, "client_id": id.ClientID,
		"username": id.Username, "roles": s.cfg.Policy.Roles(id.ClientID),
	})
}

func (s *Server) routes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"routes": s.cfg.Routes.Names()})
}

type sayRequest struct {
	To   string `json:"to"`   // route name, preferred
	Chat int64  `json:"chat"` // legacy: a declared chat id
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

	target := req.To
	if target == "" && req.Chat != 0 {
		target = strconv.FormatInt(req.Chat, 10)
	}
	chat, err := s.cfg.Routes.Resolve(target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.send(ctx, chat, req.Text); err != nil {
		log.Printf("say by %s failed: %v", identityOf(r).ClientID, err)
		writeErr(w, http.StatusBadGateway, "telegram: "+err.Error())
		return
	}
	log.Printf("say by %s to %s (%d bytes)", identityOf(r).ClientID,
		s.cfg.Routes.NameFor(chat), len(req.Text))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "to": s.cfg.Routes.NameFor(chat)})
}

// typing shows Telegram's "typing..." indicator to a recipient.
//
// Telegram clears it by itself after a few seconds, so a caller that wants it
// to persist calls this repeatedly. That is deliberately the caller's job:
// herald does not know how long anyone's work takes.
func (s *Server) typing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	chat, err := s.cfg.Routes.Resolve(req.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.typingFn(ctx, chat); err != nil {
		writeErr(w, http.StatusBadGateway, "telegram: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

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

	// Register for the wake BEFORE re-checking, so a message arriving in
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
func Poll(ctx context.Context, bot *tg.Client, st *store.Store, routes *route.Table) {
	backoff := time.Second
	for ctx.Err() == nil {
		ups, err := bot.GetUpdates(ctx, st.Offset())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if tg.IsConflict(err) {
				log.Printf("CONFLICT: another process is polling this bot, "+
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
		offset := st.Offset()
		for _, u := range ups {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			m := u.Message
			if m == nil || m.Body() == "" {
				continue
			}
			if !routes.Allowed(m.Chat.ID) {
				log.Printf("REFUSED inbound chat=%d user=%d (@%s)", m.Chat.ID, m.From.ID, m.From.Username)
				_ = bot.Send(ctx, m.Chat.ID, "not authorized.")
				continue
			}
			msgs = append(msgs, store.Message{
				ID:       u.UpdateID,
				Chat:     m.Chat.ID,
				From:     routes.NameFor(m.Chat.ID),
				Text:     m.Body(),
				Received: time.Unix(m.Date, 0).UTC(),
			})
		}
		if len(ups) == 0 {
			continue
		}
		// Persist offset and messages together, before anyone is told.
		if err := st.Append(offset, msgs); err != nil {
			log.Printf("persist: %v: not advancing offset", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, m := range msgs {
			log.Printf("inbox += from=%s %d bytes", m.From, len(m.Text))
		}
	}
}
