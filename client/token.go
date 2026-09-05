package client

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// EnvTokenSource reads a bearer token from the environment.
//
// This is the shape hush brokers into: a command.toml declares
//
//	exec = "/path/to/herald"
//	[oauth]
//	herald = "HERALD_TOKEN"
//
// and hush places the current access token in the child's environment. The
// CLI never learns where the credential came from, which is the point: the
// same binary works under a shim, under systemd with LoadCredential, or with
// a token pasted in by hand.
type EnvTokenSource struct {
	Var string
	// RefreshCmd, when set, is run to obtain a fresh token after a 401. It
	// is how a long-lived process recovers without being restarted; a
	// short-lived CLI invocation usually leaves it empty and simply exits.
	RefreshCmd []string
}

const DefaultTokenVar = "HERALD_TOKEN"

func (e *EnvTokenSource) name() string {
	if e.Var != "" {
		return e.Var
	}
	return DefaultTokenVar
}

func (e *EnvTokenSource) Token(context.Context) (string, error) {
	tok := strings.TrimSpace(os.Getenv(e.name()))
	if tok == "" {
		return "", errors.New("no token in $" + e.name() +
			", run through hush (`hush herald …`) or set it explicitly")
	}
	return tok, nil
}

func (e *EnvTokenSource) Refresh(ctx context.Context) (string, error) {
	if len(e.RefreshCmd) == 0 {
		return "", errors.New("token in $" + e.name() +
			" was rejected and this process cannot refresh it; re-run the command")
	}
	out, err := exec.CommandContext(ctx, e.RefreshCmd[0], e.RefreshCmd[1:]...).Output()
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", errors.New("refresh command produced no token")
	}
	return tok, nil
}
