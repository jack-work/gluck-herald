# herald

The message gateway: the Telegram Bot API with **names** instead of chat ids,
a durable inbox, and per-client authorization.

Herald is deliberately boring and deliberately ignorant. It knows nothing
about figaro, calendars, or anything else that might want to send you a
message — those are *callers*, and they live in their own modules and depend
on `client`.

```
        ┌───────────── spain ─────────────┐
Telegram ──poll──▶ herald ──▶ Caddy ──▶ Cloudflare
        │        (9098, loopback)        │
        └────────────────────────────────┘
                        ▲   │
             POST /v1/say│   │GET /v1/inbox
                         │   ▼
        ┌────────────────┴──────────────────┐
   kcal-notify (on spain)          figaro bridge (laptop)
   client_credentials              hush-brokered token
   roles: say                      roles: say, inbox
```

## API

| route | role | purpose |
|---|---|---|
| `GET /v1/health` | — | liveness, offset, queue depth |
| `GET /v1/whoami` | `admin` | what your token asserts |
| `GET /v1/routes` | `say` | recipient names you may address |
| `POST /v1/say` | `say` | send markdown to a named recipient |
| `GET /v1/inbox?after=&wait=` | `inbox` | long-poll for inbound messages |
| `POST /v1/inbox/ack` | `inbox` | drop messages through an id |

Long polls cap at 60s: Cloudflare kills a held request at ~100s with a 524.

## Identity and authorization

Herald verifies tokens itself. On the bearer path Caddy passes requests
through untouched, so nothing upstream has checked anything.

- **Signature** against Authelia's JWKS, RS256/RS512 only — the token does not
  get to choose how it is checked, so `alg: none` cannot apply.
- **`client_id`**, not audience. Authelia issues access tokens with an empty
  `aud` (verified against a live token, not assumed); an `aud` check would be
  a control that looks real and does nothing.
- **Roles per client.** `say` and `inbox` are separate so a notifier can
  announce events without reading the replies. Unknown client → 401 (register
  it); known client without the role → 403 (fix policy).
- **Named routes.** Callers name a recipient; herald resolves it. Undeclared
  destinations are refused however they are spelled, in both directions.

Keying on `client_id` rather than on a user is what makes service identity
work at all: a `client_credentials` token has no `preferred_username` and no
groups, so any model built on "which person is this" cannot express it.

## Delivery

At-least-once. The Telegram offset and the inbox are persisted in one fsynced
write before anyone is told; a client acks only after it has durably acted. A
crash replays rather than loses.

Telegram permits exactly **one** `getUpdates` consumer per bot. A second one
gets 409 and the two silently split the stream, so herald logs that case
loudly rather than retrying quietly.

## Client

```sh
herald say --to gluck "**done**"    # markdown → telegram HTML
herald inbox --wait 30s             # JSON
herald ack --through 42
herald routes
herald whoami
```

`$HERALD_TOKEN` carries the bearer; hush brokers it, and a hush shim makes
plain `herald …` work from any script:

```toml
# ~/.config/hush/commands/herald/command.toml
exec = "/home/gluck/go/bin/herald"

[oauth]
herald = "HERALD_TOKEN"
```

For a **service** on spain, use `client.ClientCredentials` instead: the client
secret arrives by `LoadCredential` and never leaves the box, and herald sees
only a short-lived token Authelia signed.

## Deploying

One `mkService` call; see `flake.nix`. The bot token arrives by
`LoadCredential` from sops — never `Environment=` (unit files are
world-readable in `/nix/store` forever, and in git history) and never argv
(`/proc/<pid>/cmdline` is world-readable). DynamicUser stays on: herald writes
only its own `StateDirectory`.
