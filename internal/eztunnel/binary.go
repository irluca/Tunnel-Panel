// Package eztunnel manages the eztunnel binary: the userspace tunnel
// engine from EZTunnel that the panel runs for its EZTunnel tunnels.
//
// EZTunnel publishes a SHA256SUMS file with each release, and the panel
// pins the binary's SHA-256 for the release it uses (see
// link.EzBinaryChecksums) and verifies every download against it before
// installing. A download that does not match is refused, not installed,
// and the tunnel creation that needed it fails loudly with the reason.
// The version is pinned too: a new EZTunnel release cannot change what
// this panel installs without the panel being updated to pin it.
package eztunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/drs/gre-panel/internal/link"
)

// BinaryPath is where the eztunnel binary lives, under the panel's data
// directory.
func BinaryPath(dataDir string) string {
	return filepath.Join(dataDir, "bin", link.EzBinaryName)
}

// Ensurer downloads and verifies the eztunnel binary when it is missing or
// does not match the pinned checksum.
type Ensurer struct {
	dataDir string
	client  *http.Client
	log     *slog.Logger
}

// New returns an ensurer for the given data directory.
func New(dataDir string, log *slog.Logger) *Ensurer {
	if log == nil {
		log = slog.Default()
	}
	return &Ensurer{
		dataDir: dataDir,
		client:  &http.Client{Timeout: 120 * time.Second},
		log:     log,
	}
}

// Ensure returns the path to a verified eztunnel binary, downloading it when
// it is missing or does not match the pinned checksum. A binary already on
// disk with the right checksum is left alone; a download that fails or does
// not match is an error, and nothing is installed.
func (e *Ensurer) Ensure(ctx context.Context) (string, error) {
	arch := runtime.GOARCH
	want, ok := link.EzBinaryChecksums[arch]
	if !ok {
		return "", fmt.Errorf("the panel has no pinned eztunnel binary for %s, so it cannot install one", arch)
	}
	path := BinaryPath(e.dataDir)
	if sum, err := fileSHA256(path); err == nil && sum == want {
		return path, nil
	}
	if err := e.download(ctx, path, want); err != nil {
		return "", err
	}
	return path, nil
}

// download fetches the binary from the pinned release, verifies its checksum,
// and installs it atomically. The download goes to a temporary file in the
// same directory, so a failed or interrupted download never leaves a
// truncated binary where the panel would run it.
func (e *Ensurer) download(ctx context.Context, path, want string) error {
	url, ok := link.EzBinaryURL(runtime.GOARCH)
	if !ok {
		return fmt.Errorf("the panel has no pinned eztunnel binary for %s, so it cannot install one", runtime.GOARCH)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "gre-panel")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading eztunnel from %s failed: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading eztunnel from %s failed: the release host answered HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".eztunnel-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // best effort
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, 64<<20)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	if sum != want {
		return fmt.Errorf("the downloaded eztunnel does not match its pinned checksum (got %s, want %s): refusing to install it", sum, want)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	e.log.Info("installed the eztunnel binary", "path", path, "version", link.EzBinaryVersion)
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ChecksumFor returns the pinned checksum for this host's architecture, or
// false when the panel pins no binary for it.
func ChecksumFor() (string, bool) {
	sum, ok := link.EzBinaryChecksums[runtime.GOARCH]
	return sum, ok
}

// Version is the pinned EZTunnel release.
func Version() string { return link.EzBinaryVersion }

// EnsureBinary is the package-level helper for callers that only need the
// path: it builds an ensurer over the data directory and ensures the binary.
func EnsureBinary(ctx context.Context, dataDir string) (string, error) {
	return New(dataDir, nil).Ensure(ctx)
}
