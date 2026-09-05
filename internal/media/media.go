// Package media is herald's on-disk store for Telegram attachments.
//
// The bytes live beside the state file, inside the unit's StateDirectory, and
// nowhere else. That is deliberate: herald runs as DynamicUser precisely
// because it writes only its own state and shares no file contract with any
// other unit, and an attachment store on a shared volume would trade that
// away for nothing. systemd re-chowns StateDirectory on every start, so the
// bytes survive a restart without herald owning a stable uid.
//
// Media is transient by design. It is durable against a crash, not against
// losing the disk, and its lifetime is tied to the message that carries it:
// acknowledge the message and the bytes go with it.
package media

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// idPattern is a whitelist, not a sanitizer.
//
// Every id herald mints is 32 hex characters and an optional short lowercase
// extension, so a request that does not match this cannot address a file
// outside the media directory. Path traversal is refused by construction
// rather than cleaned up after.
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}(\.[a-z0-9]{1,8})?$`)

// ValidID reports whether an id could name a stored object.
func ValidID(id string) bool { return idPattern.MatchString(id) }

type Store struct {
	dir string

	// MaxAge and MaxBytes bound the directory in the same spirit as the
	// inbox's own cap: a client that stops acknowledging must not be able to
	// fill the disk of the machine that routes the house's traffic.
	MaxAge   time.Duration
	MaxBytes int64
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("media dir: %w", err)
	}
	return &Store{dir: dir, MaxAge: 7 * 24 * time.Hour, MaxBytes: 512 << 20}, nil
}

func (s *Store) Dir() string { return s.dir }

// ID derives a stable, path-safe name from Telegram's file_unique_id.
//
// Stable matters: the same photo forwarded twice names the same object rather
// than a second copy. The hash is for shape, not secrecy: it makes the id
// URL-safe and fixed-width, and the endpoint that serves it authenticates
// separately.
func ID(fileUniqueID, ext string) string {
	sum := sha256.Sum256([]byte(fileUniqueID))
	id := hex.EncodeToString(sum[:16])
	if ext = normalizeExt(ext); ext != "" {
		id += ext
	}
	return id
}

func normalizeExt(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	if len(ext) > 9 {
		return ""
	}
	for _, r := range ext[1:] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return ext
}

// Create opens a pending object. The bytes are written to a temp file and
// named only when the writer commits, because the name depends on what the
// download turns out to be: Telegram reports the file's extension in the
// same response that carries it.
//
// Temp file, fsync, rename: the same discipline the state file uses, and for
// the same reason. A half-written screenshot that survives a power cut is
// worse than no screenshot, because it looks like a whole one.
func (s *Store) Create() (*Pending, error) {
	f, err := os.CreateTemp(s.dir, "incoming-*.tmp")
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &Pending{f: f, dir: s.dir}, nil
}

// Pending is an object being written. It is not addressable until Commit.
type Pending struct {
	f   *os.File
	dir string
}

func (p *Pending) Write(b []byte) (int, error) { return p.f.Write(b) }

// Commit fsyncs and gives the object its final name.
func (p *Pending) Commit(id string) error {
	if !ValidID(id) {
		p.Abort()
		return fmt.Errorf("media: refusing to write id %q", id)
	}
	if err := p.f.Sync(); err != nil {
		p.Abort()
		return err
	}
	name := p.f.Name()
	if err := p.f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(p.dir, id)); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// Abort discards a pending object. Safe to call after Commit.
func (p *Pending) Abort() {
	name := p.f.Name()
	p.f.Close()
	os.Remove(name)
}

// Open returns the bytes of an object, or an error a caller may treat as 404.
//
// An id that was never minted and an id whose message has been acknowledged
// are the same answer on purpose: herald reports what it holds, not what it
// once held.
func (s *Store) Open(id string) (*os.File, os.FileInfo, error) {
	if !ValidID(id) {
		return nil, nil, os.ErrNotExist
	}
	path := filepath.Join(s.dir, id)
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// Remove deletes objects, ignoring the ones already gone.
func (s *Store) Remove(ids ...string) {
	for _, id := range ids {
		if ValidID(id) {
			os.Remove(filepath.Join(s.dir, id))
		}
	}
}

// Sweep enforces the age and size caps, oldest first, and returns what it
// deleted. It is a backstop: the normal path is Ack, and anything Sweep
// removes is something no client ever came back for.
func (s *Store) Sweep() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	type item struct {
		name string
		size int64
		mod  time.Time
	}
	var items []item
	var total int64
	var removed []string
	cutoff := time.Now().Add(-s.MaxAge)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		// A .tmp left by a crash mid-write belongs to nobody.
		if strings.HasSuffix(e.Name(), ".tmp") {
			if fi.ModTime().Before(time.Now().Add(-time.Hour)) {
				os.Remove(filepath.Join(s.dir, e.Name()))
			}
			continue
		}
		if s.MaxAge > 0 && fi.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(s.dir, e.Name()))
			removed = append(removed, e.Name())
			continue
		}
		items = append(items, item{e.Name(), fi.Size(), fi.ModTime()})
		total += fi.Size()
	}

	if s.MaxBytes <= 0 || total <= s.MaxBytes {
		return removed
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.Before(items[j].mod) })
	for _, it := range items {
		if total <= s.MaxBytes {
			break
		}
		os.Remove(filepath.Join(s.dir, it.name))
		removed = append(removed, it.name)
		total -= it.size
	}
	return removed
}
