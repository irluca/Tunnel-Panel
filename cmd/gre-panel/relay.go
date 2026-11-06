package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	"github.com/drs/gre-panel/internal/grewss"
)

// runRelay is the `gre-panel relay` subcommand: it runs the GRE-over-WSS
// relay for one tunnel. The panel's systemd unit runs it, so it never
// returns while the tunnel is up — it only stops on a signal or when the
// far end goes away for good (the client redials on its own).
//
// Flags:
//
//	--tun <name>        the TUN interface to create (required)
//	--key <uint32>      the GRE key in the header of every packet (required)
//	--token <string>    the shared token that authenticates the far end (required)
//	--mtu <int>         the MTU to set on the TUN (0 leaves the default)
//	--address <cidr>    an address to add to the TUN; repeatable
//	--listen <addr>     server mode: listen here (for example "0.0.0.0:443")
//	--dial <wss-url>    client mode: dial this URL (for example "wss://1.2.3.4:443/gre-wss")
//
// Exactly one of --listen and --dial is required.
func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	tun := fs.String("tun", "", "the TUN interface to create")
	key := fs.Uint("key", 0, "the GRE key in the header of every packet the relay sends")
	inKey := fs.Uint("in-key", 0, "the GRE key expected on packets it receives (defaults to --key)")
	token := fs.String("token", "", "the shared token that authenticates the far end")
	mtu := fs.Int("mtu", 0, "the MTU to set on the TUN")
	listen := fs.String("listen", "", "server mode: listen on this address")
	dial := fs.String("dial", "", "client mode: dial this wss:// URL")
	var addresses addressList
	fs.Var(&addresses, "address", "an address to add to the TUN; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *tun == "":
		return fmt.Errorf("--tun is required")
	case *key == 0:
		return fmt.Errorf("--key is required")
	case *token == "":
		return fmt.Errorf("--token is required")
	case (*listen == "") == (*dial == ""):
		return fmt.Errorf("exactly one of --listen and --dial is required")
	case strings.HasSuffix(*listen, ":0") || strings.HasSuffix(*dial, ":0/gre-wss"):
		// A port of zero would let the listener pick a random port, which is
		// never what a tunnel wants. The panel requires a port at creation,
		// so this only fires for a record that lost one.
		return fmt.Errorf("a WSS port is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return grewss.Run(ctx, grewss.Config{
		Key:       uint32(*key),
		InKey:     uint32(*inKey),
		Token:     *token,
		Listen:    *listen,
		Dial:      *dial,
		TunName:   *tun,
		Mtu:       *mtu,
		Addresses: addresses,
	})
}

// addressList collects repeatable --address flags.
type addressList []string

func (a *addressList) String() string { return strings.Join(*a, ",") }

func (a *addressList) Set(v string) error {
	*a = append(*a, v)
	return nil
}
