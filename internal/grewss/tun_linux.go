package grewss

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

// PacketSource is where the relay reads IP packets from and writes them to.
// In production it is a TUN interface; in tests it is an in-memory queue, so
// the framing and the transport can be proved without root.
type PacketSource interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Close() error
}

// tunDevice is a TUN interface: the kernel hands the relay every IP packet
// routed to it, and every packet the relay writes is routed out of it.
type tunDevice struct {
	file *os.File
	name string
}

// OpenTun creates a TUN interface with the given name and returns it as a
// packet source. The interface is left down and unaddressed: the panel's link
// manager configures it (addresses, MTU, up) like any other interface, so the
// relay never owns that part.
func OpenTun(name string) (PacketSource, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening /dev/net/tun: %w", err)
	}
	const (
		tunsetiff = 0x400454ca
		iffTun    = 0x0001
		iffNoPi   = 0x1000
	)
	var req [40]byte
	copy(req[0:16], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = iffTun | iffNoPi
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunsetiff, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("creating the TUN interface %q: %w", name, errno)
	}
	return &tunDevice{file: f, name: name}, nil
}

// Name is the interface name, for logging.
func (t *tunDevice) Name() string { return t.name }

// Configure sets the MTU, adds the addresses and brings the interface up.
// The relay owns the TUN it created, so it configures it too: the panel's
// unit cannot run `ip` commands after a long-running relay starts, and the
// relay must not forward packets before the interface is ready.
//
// An address is "10.10.1.1/30", or "10.10.1.1 peer 10.10.1.2/32" when the
// tunnel is a single-address point-to-point link and the peer must be named
// explicitly — the same form the panel's link layer renders.
func (t *tunDevice) Configure(mtu int, addresses []string) error {
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("finding the TUN interface %q: %w", t.name, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("setting the MTU of %q: %w", t.name, err)
		}
	}
	for _, a := range addresses {
		addr, err := parseAddress(a)
		if err != nil {
			return fmt.Errorf("parsing the address %q: %w", a, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("adding %s to %q: %w", a, t.name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing %q up: %w", t.name, err)
	}
	return nil
}

// parseAddress parses "10.10.1.1/30" or "10.10.1.1 peer 10.10.1.2/32".
func parseAddress(s string) (*netlink.Addr, error) {
	if before, after, ok := strings.Cut(s, " peer "); ok {
		peerIP, prefix, ok := strings.Cut(after, "/")
		if !ok {
			return nil, fmt.Errorf("the peer address %q has no prefix length", after)
		}
		addr, err := netlink.ParseAddr(before + "/" + prefix)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(peerIP)
		if ip == nil {
			return nil, fmt.Errorf("the peer address %q is not an IP address", peerIP)
		}
		addr.Peer = &net.IPNet{IP: ip, Mask: addr.Mask}
		return addr, nil
	}
	return netlink.ParseAddr(s)
}

func (t *tunDevice) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxPacketSize)
	n, err := t.file.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *tunDevice) WritePacket(p []byte) error {
	_, err := t.file.Write(p)
	return err
}

func (t *tunDevice) Close() error { return t.file.Close() }
