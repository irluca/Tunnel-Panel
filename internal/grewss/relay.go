package grewss

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// The WebSocket subprotocol the relay speaks, and the header carrying the
// shared token. The token is what authenticates the far end: TLS alone does
// not, because the panel's certificate is self-signed and the client cannot
// verify it against a public root.
const (
	subprotocol  = "gre-wss-v1"
	tokenHeader  = "X-Gre-Wss-Token"
	defaultPath  = "/gre-wss"
	writeTimeout = 10 * time.Second
)

// Config is what a relay needs. One relay serves one tunnel.
type Config struct {
	// Key is the GRE key written into the header of every packet the relay
	// sends: the outbound key. InKey is the key it expects on packets it
	// receives: the inbound key. When InKey is zero it defaults to Key,
	// which is the panel's default — one key for both directions.
	Key   uint32
	InKey uint32
	// Token authenticates the far end. It must be the same on both ends.
	Token string
	// Path is the WebSocket path. It defaults to /gre-wss.
	Path string
	// Listen is the address the server listens on (server mode).
	Listen string
	// Dial is the wss:// URL the client dials (client mode).
	Dial string
	// TLS is the server's certificate. It is nil in client mode, where the
	// client skips verification (the token, not the certificate, is the
	// authentication) — the panel's certificate is self-signed.
	TLS *tls.Config
	// TunName is the TUN interface the relay creates and owns.
	TunName string
	// Mtu is the MTU the relay sets on the TUN. Zero leaves the default.
	Mtu int
	// Addresses are the addresses the relay adds to the TUN, in CIDR form
	// ("10.10.1.1/30"), or with an explicit peer for a single-address
	// point-to-point link ("10.10.1.1 peer 10.10.1.2/32").
	Addresses []string
	// Log, when nil, is the default logger.
	Log *slog.Logger
}

// Run opens the TUN, configures it, and runs the relay in the mode the
// config names: server (Listen set) or client (Dial set). It is the entry
// point the panel's systemd unit runs, and it returns when the context is
// cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.TunName == "" {
		return fmt.Errorf("the TUN interface name is required")
	}
	src, err := OpenTun(cfg.TunName)
	if err != nil {
		return err
	}
	defer src.Close()
	if tun, ok := src.(*tunDevice); ok {
		if err := tun.Configure(cfg.Mtu, cfg.Addresses); err != nil {
			return err
		}
	}
	relay := New(cfg, src)
	if cfg.Listen != "" {
		return relay.Serve(ctx)
	}
	if cfg.Dial != "" {
		return relay.Dial(ctx)
	}
	return fmt.Errorf("neither a listen address nor a dial URL was given")
}

// Relay moves packets between a TUN interface and a WebSocket.
type Relay struct {
	cfg Config
	src PacketSource
	log *slog.Logger

	upgrader websocket.Upgrader
	dialer   *websocket.Dialer
}

// New returns a relay for the packet source. It does not start anything.
func New(cfg Config, src PacketSource) *Relay {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	path := cfg.Path
	if path == "" {
		path = defaultPath
	}
	cfg.Path = path
	if cfg.InKey == 0 {
		cfg.InKey = cfg.Key
	}
	return &Relay{
		cfg: cfg,
		src: src,
		log: log,
		upgrader: websocket.Upgrader{
			Subprotocols: []string{subprotocol},
			// The origin is the far end of a tunnel the operator built, not a
			// browser, so there is no Origin header worth checking. The token
			// is the authentication.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		dialer: &websocket.Dialer{
			Subprotocols:     []string{subprotocol},
			HandshakeTimeout: 10 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// Serve listens for the far end (server mode) and relays until ctx is done.
// It returns when the context is cancelled or the connection fails.
func (r *Relay) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(r.cfg.Path, r.handleConnection)
	tlsCfg := r.cfg.TLS
	if tlsCfg == nil {
		// No certificate was given, so one is generated for this run. The
		// client cannot verify it against a public root anyway (the panel's
		// certificate is self-signed), and the token, not the certificate,
		// is the authentication — so an ephemeral certificate loses nothing.
		var err error
		tlsCfg, err = selfSignedCert()
		if err != nil {
			return fmt.Errorf("generating the server certificate: %w", err)
		}
	}
	srv := &http.Server{
		Addr:      r.cfg.Listen,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}
	ln, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", r.cfg.Listen, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err = srv.Serve(tlsLn)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Dial connects to the far end (client mode) and relays until ctx is done.
func (r *Relay) Dial(ctx context.Context) error {
	for {
		conn, err := r.dialOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.log.Error("dialling the far end failed, retrying", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
			continue
		}
		// One connection at a time: when it ends, dial again.
		r.relay(ctx, conn)
		if ctx.Err() != nil {
			return nil
		}
	}
}

func (r *Relay) dialOnce(ctx context.Context) (*websocket.Conn, error) {
	header := http.Header{}
	header.Set(tokenHeader, r.cfg.Token)
	conn, _, err := r.dialer.DialContext(ctx, r.cfg.Dial, header)
	if err != nil {
		return nil, fmt.Errorf("dialling %s: %w", r.cfg.Dial, err)
	}
	return conn, nil
}

func (r *Relay) handleConnection(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get(tokenHeader) != r.cfg.Token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := r.upgrader.Upgrade(w, req, nil)
	if err != nil {
		r.log.Error("upgrading the WebSocket failed", "error", err)
		return
	}
	r.relay(req.Context(), conn)
}

// relay forwards packets in both directions until one side ends, then closes
// the other. It returns when both directions have stopped.
func (r *Relay) relay(ctx context.Context, conn *websocket.Conn) {
	defer conn.Close()
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	// TUN -> WebSocket: wrap each IP packet in GRE and send it.
	go func() {
		defer stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			default:
			}
			pkt, err := r.src.ReadPacket()
			if err != nil {
				return
			}
			gre, err := Encapsulate(pkt, r.cfg.Key)
			if err != nil {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := conn.WriteMessage(websocket.BinaryMessage, gre); err != nil {
				return
			}
		}
	}()

	// WebSocket -> TUN: unwrap each GRE packet and write the IP packet out.
	go func() {
		defer stop()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			ip, err := Decapsulate(msg, r.cfg.InKey)
			if err != nil {
				r.log.Warn("dropping a packet that is not our GRE", "error", err)
				continue
			}
			if err := r.src.WritePacket(ip); err != nil {
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
	_ = conn.Close()
}

// selfSignedCert generates a short-lived self-signed certificate for the
// server. It is ephemeral: a new one is made on every start, because the
// client verifies the token, not the certificate.
func selfSignedCert() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
