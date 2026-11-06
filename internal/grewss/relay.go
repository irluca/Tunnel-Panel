package grewss

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
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
	// Key is the GRE key in the header of every packet.
	Key uint32
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
	// Log, when nil, is the default logger.
	Log *slog.Logger
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
	srv := &http.Server{
		Addr:      r.cfg.Listen,
		Handler:   mux,
		TLSConfig: r.cfg.TLS,
	}
	ln, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", r.cfg.Listen, err)
	}
	tlsLn := tls.NewListener(ln, r.cfg.TLS)
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
			ip, err := Decapsulate(msg, r.cfg.Key)
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
