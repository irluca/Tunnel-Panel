package link

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
)

// GRE-over-WSS defaults and helpers.
const (
	// WssDefaultPort is the TCP port a GRE-over-WSS tunnel serves on when the
	// operator does not choose one. 443 is the HTTPS port, which is the one a
	// path that filters GRE is least likely to block.
	WssDefaultPort = 443
	// WssTokenBytes is the length of the shared token, in bytes (hex-encoded
	// to twice that many characters).
	WssTokenBytes = 16
	// WssModeListen is the side that serves the WebSocket.
	WssModeListen = "listen"
	// WssModeDial is the side that connects to it.
	WssModeDial = "dial"
)

// GenerateWssToken returns a fresh random shared token as 32 hexadecimal
// characters.
func GenerateWssToken() (string, error) {
	token := make([]byte, WssTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generating a WSS token: %w", err)
	}
	return hex.EncodeToString(token), nil
}

// ParseWssToken checks that a token is 32 hexadecimal characters.
func ParseWssToken(s string) error {
	if len(s) != WssTokenBytes*2 {
		return fmt.Errorf("a WSS token is %d hexadecimal characters", WssTokenBytes*2)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("a WSS token is hexadecimal: %w", err)
	}
	return nil
}

// RelayArgs builds the command line that runs the GRE-over-WSS relay for a
// tunnel: the panel binary, the relay subcommand, and the tunnel's
// parameters. binary is the path to the gre-panel binary.
func RelayArgs(binary string, spec TunnelSpec, addresses []Address) []string {
	args := []string{binary, "relay",
		"--tun", spec.Name,
		"--token", spec.WssToken,
	}
	if spec.OKey != nil {
		args = append(args, "--key", strconv.FormatUint(uint64(*spec.OKey), 10))
	}
	if spec.IKey != nil {
		args = append(args, "--in-key", strconv.FormatUint(uint64(*spec.IKey), 10))
	}
	if spec.Mtu > 0 {
		args = append(args, "--mtu", strconv.Itoa(spec.Mtu))
	}
	for _, a := range addresses {
		args = append(args, "--address", addressText(a))
	}
	if spec.WssMode == WssModeListen {
		args = append(args, "--listen", "0.0.0.0:"+strconv.Itoa(spec.WssPort))
	} else {
		args = append(args, "--dial", "wss://"+spec.Remote+":"+strconv.Itoa(spec.WssPort)+"/gre-wss")
	}
	return args
}

// addressText renders an address the way the relay's --address flag takes
// it: "10.10.1.1/30", or "10.10.1.1 peer 10.10.1.2/32" for a single-address
// point-to-point link.
func addressText(a Address) string {
	s := a.Address + "/" + strconv.Itoa(a.PrefixLength)
	if a.Peer != "" {
		s = a.Address + " peer " + a.Peer + "/" + strconv.Itoa(a.PrefixLength)
	}
	return s
}
