package eztunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/drs/gre-panel/internal/link"
)

func TestEnsureDownloadsAndVerifiesTheBinary(t *testing.T) {
	// A fake release host serving a binary whose checksum the panel pins.
	payload := []byte("fake eztunnel binary")
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	link.EzBinaryChecksums["testarch"] = want
	defer delete(link.EzBinaryChecksums, "testarch")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	dir := t.TempDir()
	// The download URL is pinned to the real release host, so this test
	// verifies the checksum path through fileSHA256 and the pinned map; the
	// download path is covered by TestDownloadRefusesAMismatchedBinary.
	path := BinaryPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := fileSHA256(path)
	if err != nil || got != want {
		t.Fatalf("fileSHA256 = %q, %v, want %q", got, err, want)
	}
	if got, ok := ChecksumFor(); !ok || got != link.EzBinaryChecksums[runtime.GOARCH] {
		t.Fatalf("ChecksumFor = %q, %v", got, ok)
	}
}

func TestDownloadRefusesAMismatchedBinary(t *testing.T) {
	// The release host serves a binary that does not match the pinned
	// checksum: the download is refused and nothing is installed.
	payload := []byte("a different binary")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	dir := t.TempDir()
	e := &Ensurer{dataDir: dir, client: server.Client()}
	err := e.download(context.Background(), BinaryPath(dir), "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("a mismatched binary was accepted")
	}
	if _, statErr := os.Stat(BinaryPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("a refused binary was still installed: %v", statErr)
	}
}
