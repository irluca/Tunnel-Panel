package grewss

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeSource is an in-memory packet source: packets written to it are queued
// for ReadPacket, and packets read from it are recorded.
type fakeSource struct {
	mu       sync.Mutex
	incoming [][]byte
	read     chan []byte
	written  [][]byte
	closed   bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{read: make(chan []byte, 64)}
}

func (f *fakeSource) ReadPacket() ([]byte, error) {
	pkt, ok := <-f.read
	if !ok {
		return nil, io.EOF
	}
	return pkt, nil
}

func (f *fakeSource) WritePacket(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return io.EOF
	}
	f.written = append(f.written, append([]byte(nil), p...))
	return nil
}

func (f *fakeSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.read)
	}
	return nil
}

// feed puts a packet into the source's read queue.
func (f *fakeSource) feed(p []byte) { f.read <- p }

func (f *fakeSource) writtenPackets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.written...)
}

// selfSigned returns a TLS config with a freshly generated self-signed
// certificate, for the test server.
func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// TestRelayCarriesPacketsOverWSS proves the whole path: a packet written to
// the client's TUN arrives at the server's TUN, and a packet written to the
// server's TUN arrives at the client's — both over a TLS WebSocket, with the
// GRE header and the key in between.
func TestRelayCarriesPacketsOverWSS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverSrc := newFakeSource()
	server := New(Config{
		Key: 12345, Token: "shared-token", Listen: "127.0.0.1:0",
		TLS: selfSigned(t),
	}, serverSrc)
	// Serve on an ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc(server.cfg.Path, server.handleConnection)
		srv := &http.Server{Handler: mux, TLSConfig: server.cfg.TLS}
		_ = srv.Serve(tls.NewListener(ln, server.cfg.TLS))
	}()

	clientSrc := newFakeSource()
	client := New(Config{
		Key: 12345, Token: "shared-token",
		Dial: "wss://" + ln.Addr().String() + "/gre-wss",
	}, clientSrc)
	go func() { _ = client.Dial(ctx) }()

	// Give the client time to connect.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("the client never connected")
		}
		time.Sleep(50 * time.Millisecond)
		// The connection is up once the server has a packet path: feed a
		// packet and see if it arrives.
		clientSrc.feed(ipv4Packet())
		time.Sleep(50 * time.Millisecond)
		if len(serverSrc.writtenPackets()) > 0 {
			break
		}
	}

	// Client -> server.
	got := serverSrc.writtenPackets()
	if len(got) == 0 || !bytes.Equal(got[0], ipv4Packet()) {
		t.Fatalf("server received %v, want the IPv4 packet", got)
	}

	// Server -> client.
	serverSrc.feed(ipv6Packet())
	deadline = time.Now().Add(5 * time.Second)
	for len(clientSrc.writtenPackets()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	got = clientSrc.writtenPackets()
	if len(got) == 0 || !bytes.Equal(got[0], ipv6Packet()) {
		t.Fatalf("client received %v, want the IPv6 packet", got)
	}
}

// TestRelayRejectsAWrongToken proves the token is the authentication: a
// client with the wrong token gets a 401 and no packets flow.
func TestRelayRejectsAWrongToken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := New(Config{
		Key: 12345, Token: "shared-token", Listen: ln.Addr().String(),
		TLS: selfSigned(t),
	}, newFakeSource())
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc(server.cfg.Path, server.handleConnection)
		srv := &http.Server{Handler: mux, TLSConfig: server.cfg.TLS}
		_ = srv.Serve(tls.NewListener(ln, server.cfg.TLS))
	}()

	dialer := &websocket.Dialer{
		Subprotocols:    []string{subprotocol},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	header := http.Header{}
	header.Set(tokenHeader, "wrong-token")
	_, resp, err := dialer.Dial("wss://"+ln.Addr().String()+"/gre-wss", header)
	if err == nil {
		t.Fatal("a client with the wrong token was let in")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("response = %v, want 401", resp)
	}
}
