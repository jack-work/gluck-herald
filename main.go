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

	gauthz "github.com/jack-work/gluck-authz"
	"github.com/jack-work/gluck-herald/client"
	"github.com/jack-work/gluck-herald/internal/authz"
	"github.com/jack-work/gluck-herald/internal/media"
	"github.com/jack-work/gluck-herald/internal/route"
	"github.com/jack-work/gluck-herald/internal/server"
	"github.com/jack-work/gluck-herald/internal/store"
	"github.com/jack-work/gluck-herald/internal/tg"
)

const usage = `herald: message gateway (telegram, with names)

Server:
  herald serve                        run the API and the telegram poller

Client:
  herald say --to <name> <markdown>   send a message ("-" reads stdin)
  herald inbox [--wait D]             print pending messages as JSON
  herald ack --through <id>           drop messages through an id
  herald media <id> [-o <file>]       fetch one attachment ("-" writes stdout)
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
	case "media":
		err = cmdMedia(os.Args[2:])
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
// file: those are world-readable in /nix/store forever, and in git history.
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
	mediaDir := fs.String("media", envOr("HERALD_MEDIA", ""), "attachment directory (default: media/ beside the state file)")
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

	// Register the command menu every start. Telegram stores it, so it
	// outlives the program that set it: this bot token still carried a
	// previous tenant's commands long after that program was gone. Setting
	// it here makes the menu a property of the running code rather than of
	// whoever last remembered.
	if before, err := bot.Commands(ctx); err == nil {
		if !sameCommands(before, botCommands) {
			if err := bot.SetCommands(ctx, botCommands); err != nil {
				log.Printf("setMyCommands: %v (menu may be stale)", err)
			} else {
				log.Printf("commands: replaced %d stale entr(ies) with %d current", len(before), len(botCommands))
			}
		}
	} else {
		log.Printf("getMyCommands: %v", err)
	}

	if strings.TrimSpace(*mediaDir) == "" {
		*mediaDir = filepath.Join(filepath.Dir(*statePath), "media")
	}

	st, err := store.Open(*statePath)
	if err != nil {
		return err
	}

	// Media lives beside the state file, which puts it inside the unit's
	// StateDirectory without the unit having to say so twice.
	ms, err := media.Open(*mediaDir)
	if err != nil {
		return err
	}
	// The store is what knows when a message stops existing, so it is what
	// releases the bytes: an attachment that outlives its message is a leak.
	st.DropMedia = ms.Remove
	if n := ms.Sweep(); len(n) > 0 {
		log.Printf("media: swept %d expired object(s) at startup", len(n))
	}

	srv := server.New(server.Config{
		Bot:      bot,
		Store:    st,
		Policy:   policy,
		Routes:   routes,
		Media:    ms,
		Verifier: &gauthz.Verifier{JWKSURL: *jwksURL, Issuer: *issuer, ClientIDs: policy.Clients()},
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	go server.Poll(ctx, bot, st, routes, ms)
	go sweepMedia(ctx, ms)
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

// cmdMedia fetches one attachment by the id the inbox reported.
//
// It exists so the path can be exercised by hand, without a bridge and
// without an aria: after a deploy, send a photo and fetch it. A feature that
// can only be tested by the thing that consumes it is a feature nobody can
// diagnose.
func cmdMedia(args []string) error {
	fs := flag.NewFlagSet("media", flag.ExitOnError)
	out := fs.String("o", "", `write to this file, or "-" for stdout (default: the id, in the current directory)`)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: herald media <id> [-o <file>]")
	}
	id := fs.Arg(0)

	dst := *out
	if dst == "" {
		dst = id
	}
	var w io.Writer = os.Stdout
	if dst != "-" {
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	n, err := newClient().Media(ctx, id, w)
	if err != nil {
		return err
	}
	if dst != "-" {
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", dst, n)
	}
	return nil
}

// botCommands is the menu Telegram shows behind the slash key.
//
// It names what exists now: figaro arias reached through the bridge. Nothing
// here is kept for compatibility with an older spelling, because nothing
// depends on those but habit, and a menu offering commands that do nothing is
// worse than a short one.
var botCommands = []tg.Command{
	{Command: "aria", Description: "which aria this chat is bound to"},
	{Command: "arias", Description: "recent arias to choose from"},
	{Command: "bind", Description: "point this chat at an aria or @role"},
	{Command: "new", Description: "mint a fresh aria and bind to it"},
	{Command: "roles", Description: "roles and who holds them"},
	{Command: "hup", Description: "stop the running turn, keep anything queued"},
	{Command: "cut", Description: "stop it and discard the queue, handed back to you"},
	{Command: "help", Description: "what these do"},
}

func sameCommands(a, b []tg.Command) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
	noFooter := fs.Bool("no-footer", false, "omit the sender footer")
	from := fs.String("from", envOr("HERALD_FROM", ""), "label for the footer, normally the sender's mantra")
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
	if !*noFooter {
		text += senderFooter(*from)
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

// senderFooter identifies who sent a message.
//
// Several arias share one chat, so a reply with no attribution leaves the
// reader guessing which of them answered. FIGARO_ARIA is set by the daemon
// inside an aria's bash tool, so the id costs nothing and needs no plumbing.
//
// The label is passed in rather than looked up: an aria knows its own mantra,
// and asking herald to fetch it would make a message gateway depend on
// figaro, which is the coupling herald exists to avoid.
//
// Attribution, not authentication. Anything can set these. That is fine for a
// label and would not be for a permission.
func senderFooter(label string) string {
	aria := strings.TrimSpace(os.Getenv("FIGARO_ARIA"))
	label = strings.TrimSpace(label)
	switch {
	case aria == "" && label == "":
		return ""
	case aria == "":
		return "\n\n_" + label + "_"
	case label == "":
		return "\n\n`" + aria + "`"
	default:
		return "\n\n`" + aria + "` _" + label + "_"
	}
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

// sweepMedia enforces the age and size caps on a slow timer.
//
// It is a backstop, not the mechanism: attachments are normally released the
// moment their message is acknowledged. This collects what a client that
// stopped polling left behind, so an inbox nobody drains cannot fill the disk
// of the machine that also routes the house.
func sweepMedia(ctx context.Context, ms *media.Store) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if gone := ms.Sweep(); len(gone) > 0 {
				log.Printf("media: swept %d object(s) past the retention caps", len(gone))
			}
		}
	}
}
