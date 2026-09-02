# herald

The authenticated message gateway. Telegram on one side, an OIDC-protected
HTTP API on the other, and figaro on your laptop.

```
        ┌───────────── spain ─────────────┐
Telegram ──poll──▶ herald ──▶ Caddy ──▶ Cloudflare
        │        (9098, loopback)        │
        └────────────────────────────────┘
                        ▲   │
             POST /v1/say│   │GET /v1/inbox  (long poll)
                        │   ▼
                   herald CLI  ──▶  figaro send   (laptop)
```

**The laptop pulls.** spain never reaches into the figaro store, needs no
credential for your machine, and a compromised spain cannot push anything
into an aria. It also means herald does not depend on a figaro daemon
existing on spain — which is what unblocked it.

## API

| route | auth | purpose |
|---|---|---|
| `GET /v1/health` | none | liveness, offset, queue depth |
| `GET /v1/whoami` | bearer | what your token asserts |
| `POST /v1/say` | bearer | send markdown to an allowed chat |
| `GET /v1/inbox?after=&wait=` | bearer | long-poll for inbound DMs |
| `POST /v1/inbox/ack` | bearer | drop messages through an id |

Long polls are capped at 60s: Cloudflare kills a held request at about 100s
and returns 524.

## Authorization

Herald verifies the JWT itself. On the bearer path Caddy passes the request
through untouched, so nothing upstream has checked anything.

- **Signature** against Authelia's JWKS, RS256/RS512 only. The token does not
  get to choose how it is checked (`alg: none` is refused).
- **`client_id` allowlist** — *not* audience. Authelia issues access tokens
  with an empty `aud`, verified against a live token; an `aud` check would be
  a control that looks real and does nothing. A kfin token dies on this line.
- **issuer**, **exp/nbf** with 60s skew.
- **lldap group** (`requiredGroup`), coarse and optional.
- **chat allowlist** — the caller may name a chat, but only from a fixed set.
  A gateway whose caller can name any destination is an open relay that signs
  its own requests.

## Delivery

At-least-once. The Telegram offset and the inbox are persisted in one fsynced
write before anyone is told, and a client acks only after it has durably
acted. A crash replays; it does not lose.

Telegram permits exactly **one** `getUpdates` consumer per bot. A second one
gets 409 and the two silently split the stream — so figbot must be retired,
not merely left running.

## Client

```sh
herald say --chat 487734915 "**done**"      # markdown → telegram HTML
herald pump --aria 8fc9ebed                 # bridge: inbox → figaro → reply
herald inbox --wait 30s                     # raw JSON
herald whoami
```

The token comes from `$HERALD_TOKEN`. The CLI is deliberately
credential-agnostic — hush brokers it in, and nothing here knows what a vault
is:

```toml
# ~/.config/hush/commands/herald/command.toml
exec = "/home/gluck/go/bin/herald"

[oauth]
herald = "HERALD_TOKEN"
```

With a hush shim installed (`hush shim install herald`), plain `herald say …`
works from any script.

## Deploying

One `mkService` call; see `flake.nix`. The bot token arrives by
`LoadCredential` from sops — never `Environment=` (unit files are
world-readable in `/nix/store` forever, and in git history) and never argv
(`/proc/<pid>/cmdline` is world-readable). DynamicUser stays on: herald
writes only its own `StateDirectory`.
