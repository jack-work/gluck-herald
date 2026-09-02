// Command herald is both halves of the message gateway: the server that
// runs on spain and the CLI that talks to it.
//
// One binary because the two share the wire types, and because a client
// that drifts from its server is a class of bug worth designing out.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jack-work/gluck-herald/internal/auth"
	"github.com/jack-work/gluck-herald/internal/client"
	"github.com/jack-work/gluck-herald/internal/server"
	"github.com/jack-work/gluck-herald/internal/store"
	"github.com/jack-work/gluck-herald/internal/tg"
)

const usage = `herald — authenticated message gateway

Server (on spain):
  herald serve                     run the API and the telegram poller

Client:
  herald say [--chat N] <markdown> send a message (reads stdin with "-")
  herald pump [--aria ID]          long-poll the inbox, route into figaro
  herald inbox [--wait D]          print pending messages as JSON
  herald whoami                    show the identity your token asserts
  herald health                    server health (no auth)

Client environment:
  HERALD_API        base URL (default https://herald.kelliher.info)
  HERALD_TOKEN      bearer token; normally injected by hush
  HERALD_CHAT       default chat id for say
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("herald ")

	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "say":
		err = runSay(os.Args[2:])
	case "pump":
		err = runPump(os.Args[2:])
	case "inbox":
		err = runInbox(os.Args[2:])
	case "whoami":
		err = runWhoAmI(os.Args[2:])
	case "health":
		err = runHealth(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "herald: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "herald: "+err.Error())
		os.Exit(1)
	}
}

// ---------- server ----------

// telegramToken reads the bot token from a systemd credential, falling back
// to the environment for local development.
//
// LoadCredential is the delivery of record: the value lands in a per-unit
// tmpfs at 0400 and vanishes with the unit. Never Environment= in a unit
// file — those are world-readable in /nix/store forever, and in git history.
func telegramToken() (string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		b, err := os.ReadFile(filepath.Join(dir, "token"))
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("read credential: %w", err)
		}
	}
	if t := strings.TrimSpace(os.Getenv("HERALD_TELEGRAM_TOKEN")); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("no telegram token: expected $CREDENTIALS_DIRECTORY/token or $HERALD_TELEGRAM_TOKEN")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", envOr("HERALD_ADDR", "127.0.0.1:"+envOr("PORT", "9098")), "listen address")
	statePath := fs.String("state", envOr("HERALD_STATE", defaultStatePath()), "state file")
	jwksURL := fs.String("jwks", envOr("HERALD_JWKS", "http://127.0.0.1:9091/jwks.json"), "Authelia JWKS URL")
	issuer := fs.String("issuer", envOr("HERALD_ISSUER", "https://auth.kelliher.info"), "expected token issuer")
	clientIDs := fs.String("client-ids", envOr("HERALD_CLIENT_IDS", "herald"), "comma-separated OIDC client_id allowlist")
	group := fs.String("group", envOr("HERALD_GROUP", ""), "required lldap group")
	chats := fs.String("chats", envOr("HERALD_CHATS", ""), "comma-separated allowed telegram chat ids")
	if err := fs.Parse(args); err != nil {
		return err
	}

	token, err := telegramToken()
	if err != nil {
		return err
	}
	bot := tg.New(token)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	me, err := bot.Me(ctx)
	if err != nil {
		return fmt.Errorf("telegram getMe: %w", err)
	}

	st, err := store.Open(*statePath)
	if err != nil {
		return err
	}
	allowed := parseChats(*chats)

	srv := server.New(server.Config{
		Bot:   bot,
		Store: st,
		Verifier: &auth.Verifier{
			JWKSURL:   *jwksURL,
			Issuer:    *issuer,
			ClientIDs: splitComma(*clientIDs),
		},
		RequiredGroup: *group,
		AllowedChats:  allowed,
	})

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: srv.Handler(),
		// Generous, because /v1/inbox holds a request open for up to 60s.
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	go server.Poll(ctx, bot, st, allowed)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	offset, pending := st.Stats()
	log.Printf("bot=@%s listening=%s state=%s offset=%d pending=%d clients=%s group=%q chats=%v",
		me, *addr, *statePath, offset, pending, *clientIDs, *group, keysOf(allowed))

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	log.Printf("stopped")
	return nil
}

func defaultStatePath() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		// systemd hands a colon-separated list; the first is ours.
		return filepath.Join(strings.Split(d, ":")[0], "state.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "herald", "state.json")
}

// ---------- client ----------

func newClient() *client.Client {
	return client.New(
		envOr("HERALD_API", "https://herald.kelliher.info"),
		&client.EnvTokenSource{Var: client.DefaultTokenVar},
	)
}

func runSay(args []string) error {
	fs := flag.NewFlagSet("say", flag.ExitOnError)
	chat := fs.Int64("chat", envInt("HERALD_CHAT", 0), "target chat id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	text := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(text) == "" || text == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("nothing to say (give text as arguments or on stdin)")
	}
	if *chat == 0 {
		return fmt.Errorf("no chat: pass --chat or set HERALD_CHAT")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := newClient().Say(ctx, *chat, text); err != nil {
		return err
	}
	fmt.Printf("sent to chat %d\n", *chat)
	return nil
}

func runInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	after := fs.Int64("after", 0, "only messages newer than this id")
	wait := fs.Duration("wait", 0, "long-poll for up to this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait+90*time.Second)
	defer cancel()

	msgs, err := newClient().Inbox(ctx, *after, *wait)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(msgs)
}

// runPump is the bridge: long-poll the inbox, hand each message to a local
// figaro aria, send the reply back.
//
// This runs on the laptop, which is the whole point of the pull design —
// spain never reaches into the figaro store, and needs no credential for
// this machine.
func runPump(args []string) error {
	fs := flag.NewFlagSet("pump", flag.ExitOnError)
	aria := fs.String("aria", envOr("HERALD_ARIA", ""), "figaro aria to route messages into")
	wait := fs.Duration("wait", 55*time.Second, "long-poll window (server caps at 60s)")
	once := fs.Bool("once", false, "handle at most one batch, then exit")
	dryRun := fs.Bool("dry-run", false, "print what would be sent to figaro, do not call it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c := newClient()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("pumping %s -> aria %s", c.BaseURL, orNone(*aria))
	for ctx.Err() == nil {
		msgs, err := c.Inbox(ctx, 0, *wait)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("inbox: %v (retrying in 5s)", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, m := range msgs {
			if err := handle(ctx, c, m, *aria, *dryRun); err != nil {
				log.Printf("handling %d: %v", m.ID, err)
				continue
			}
			// Acknowledge only after the reply is out: delivery is
			// at-least-once, so a crash replays rather than loses.
			if err := c.Ack(ctx, m.ID); err != nil {
				log.Printf("ack %d: %v", m.ID, err)
			}
		}
		if *once {
			break
		}
	}
	return nil
}

func handle(ctx context.Context, c *client.Client, m client.Message, aria string, dryRun bool) error {
	log.Printf("chat=%d (@%s): %.80q", m.Chat, m.From, m.Text)
	prompt := "[telegram · via herald] " + m.Text

	if dryRun {
		fmt.Printf("would send to aria %s: %s\n", orNone(aria), prompt)
		return nil
	}

	args := []string{"-A", "send", "-r"}
	if aria != "" {
		args = append(args, "--id", aria)
	}
	args = append(args, "--", prompt)

	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(cctx, "figaro", args...).Output()
	reply := strings.TrimSpace(string(out))
	if err != nil {
		reply = "⚠️ figaro: " + err.Error()
		if reply == "" {
			reply = "⚠️ figaro failed with no output"
		}
	}
	if reply == "" {
		reply = "(no output)"
	}

	sendCtx, sendCancel := context.WithTimeout(ctx, 90*time.Second)
	defer sendCancel()
	return c.Say(sendCtx, m.Chat, reply)
}

func runWhoAmI(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w, err := newClient().WhoAmI(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(w)
}

func runHealth(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := newClient().Health(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(h)
}

// ---------- small helpers ----------

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int64) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(key)), 10, 64); err == nil {
		return v
	}
	return fallback
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseChats(s string) map[int64]bool {
	out := map[int64]bool{}
	for _, p := range splitComma(s) {
		if id, err := strconv.ParseInt(p, 10, 64); err == nil {
			out[id] = true
		}
	}
	return out
}

func keysOf(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(pid-bound)"
	}
	return s
}
