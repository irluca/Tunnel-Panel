package grewss

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
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
