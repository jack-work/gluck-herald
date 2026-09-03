// Command herald is the message gateway: the Telegram Bot API with names
// instead of chat ids, a durable inbox, and per-client authorization.
//
// It is deliberately boring and deliberately ignorant. It knows nothing about
// figaro, calendars, or anything else that might want to send you a message;
// those live in their own modules and depend on this one's client package.
// Herald's whole job is: take a name and some markdown, deliver it; take
// what Telegram sends back, hold it until someone claims it.
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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jack-work/gluck-herald/client"
	"github.com/jack-work/gluck-herald/internal/auth"
	"github.com/jack-work/gluck-herald/internal/authz"
	"github.com/jack-work/gluck-herald/internal/route"
	"github.com/jack-work/gluck-herald/internal/server"
	"github.com/jack-work/gluck-herald/internal/store"
	"github.com/jack-work/gluck-herald/internal/tg"
)

const usage = `herald — message gateway (telegram, with names)

Server:
  herald serve                        run the API and the telegram poller

Client:
  herald say --to <name> <markdown>   send a message ("-" reads stdin)
  herald inbox [--wait D]             print pending messages as JSON
  herald ack --through <id>           drop messages through an id
  herald routes                       list recipient names
  herald whoami                       show what your token asserts
  herald health                       server health (no auth)

Client environment:
  HERALD_API     base URL (default https://herald.kelliher.info)
  HERALD_TOKEN   bearer token; normally injected by hush
  HERALD_TO      default recipient name
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
	case "inbox":
		err = runInbox(os.Args[2:])
	case "ack":
		err = runAck(os.Args[2:])
	case "routes":
		err = runRoutes(os.Args[2:])
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
	policyJSON := fs.String("policy", envOr("HERALD_POLICY", ""), `client roles, JSON: {"herald":["say","inbox","admin"]}`)
	routesJSON := fs.String("routes", envOr("HERALD_ROUTES", ""), `recipient names, JSON: {"gluck":"487734915"}`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	var policySpec map[string][]string
	if err := json.Unmarshal([]byte(orEmptyJSON(*policyJSON)), &policySpec); err != nil {
		return fmt.Errorf("--policy: %w", err)
	}
	policy, err := authz.NewPolicy(policySpec)
	if err != nil {
		return err
	}

	var routeSpec map[string]string
	if err := json.Unmarshal([]byte(orEmptyJSON(*routesJSON)), &routeSpec); err != nil {
		return fmt.Errorf("--routes: %w", err)
	}
	routes, err := route.NewTable(routeSpec)
	if err != nil {
		return err
	}
	if routes.Empty() {
		// Refuse to run as an unaddressable gateway rather than start and
		// reject everything at request time.
		return fmt.Errorf("no routes declared: herald could neither send nor accept anything")
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

	srv := server.New(server.Config{
		Bot:      bot,
		Store:    st,
		Policy:   policy,
		Routes:   routes,
		Verifier: &auth.Verifier{JWKSURL: *jwksURL, Issuer: *issuer, ClientIDs: policy.Clients()},
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	go server.Poll(ctx, bot, st, routes)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	offset, pending := st.Stats()
	log.Printf("bot=@%s listening=%s offset=%d pending=%d routes=%v clients=%v",
		me, *addr, offset, pending, routes.Names(), policy.Clients())
	for _, c := range policy.Clients() {
		log.Printf("  client %-16s roles=%v", c, policy.Roles(c))
	}

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	log.Printf("stopped")
	return nil
}

func defaultStatePath() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
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
	to := fs.String("to", envOr("HERALD_TO", ""), "recipient name (see `herald routes`)")
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
	if *to == "" {
		return fmt.Errorf("no recipient: pass --to or set HERALD_TO")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := newClient().Say(ctx, *to, text); err != nil {
		return err
	}
	fmt.Printf("sent to %s\n", *to)
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
	return dump(msgs)
}

func runAck(args []string) error {
	fs := flag.NewFlagSet("ack", flag.ExitOnError)
	through := fs.Int64("through", 0, "drop messages up to and including this id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return newClient().Ack(ctx, *through)
}

func runRoutes(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	names, err := newClient().Routes(ctx)
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func runWhoAmI(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w, err := newClient().WhoAmI(ctx)
	if err != nil {
		return err
	}
	return dump(w)
}

func runHealth(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := newClient().Health(ctx)
	if err != nil {
		return err
	}
	return dump(h)
}

// ---------- helpers ----------

func dump(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func orEmptyJSON(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}
