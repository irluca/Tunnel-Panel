//go:build linux

package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/drs/gre-panel/internal/i18n"
)

// createESP builds an ESP tunnel: the xfrm interface, then the two security
// associations and the two policies bound to it by interface identifier.
// The states and policies are removed first when they already exist, so a
// retry after a partial failure does not trip over its own leftovers.
func (n *Netlink) createESP(ctx context.Context, spec TunnelSpec, local, remote net.IP) error {
	if err := checkEspSpec(ctx, spec); err != nil {
		return err
	}
	ifid := int(spec.EspIfID)

	// Clear any leftovers from a previous attempt with this identity.
	deleteESPByIfID(ctx, ifid)

	attrs := netlink.NewLinkAttrs()
	attrs.Name = spec.Name
	if spec.Mtu > 0 {
		attrs.MTU = spec.Mtu
	}
	if spec.TxQueueLength != nil {
		attrs.TxQLen = *spec.TxQueueLength
	} else {
		attrs.TxQLen = -1 // leave the kernel default alone
	}
	link := &netlink.Xfrmi{LinkAttrs: attrs, Ifid: uint32(ifid)}
	trace(ctx, fmt.Sprintf("LinkAdd %s type xfrm if_id %d", spec.Name, ifid), nil)
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s", ErrExists, spec.Name)
		}
		return i18n.Errorf(ctx, "creating %s: %w", spec.Name, err)
	}

	// From here on a failure removes what was just built, so the host is
	// not left with half a tunnel.
	created := []func() error{}
	cleanup := func() {
		for i := len(created) - 1; i >= 0; i-- {
			_ = created[i]()
		}
		_ = netlink.LinkDel(link)
	}

	for _, outbound := range []bool{true, false} {
		src, dst := local, remote
		spi := spec.EspSPIOut
		if !outbound {
			src, dst = remote, local
			spi = spec.EspSPIIn
		}
		state := &netlink.XfrmState{
			Src: src, Dst: dst, Proto: netlink.XFRM_PROTO_ESP,
			Mode: netlink.XFRM_MODE_TRANSPORT, Spi: int(spi),
			Reqid: ifid, Ifid: ifid, ReplayWindow: EspReplayWindow,
			Aead: &netlink.XfrmStateAlgo{Name: EspAeadName, Key: spec.EspKey, ICVLen: EspICVLen},
		}
		// The trace carries the SPI and the endpoints, never the key.
		trace(ctx, fmt.Sprintf("XfrmStateAdd %s -> %s proto esp spi 0x%x", src, dst, spi), nil)
		if err := netlink.XfrmStateAdd(state); err != nil {
			cleanup()
			return i18n.Errorf(ctx, "adding the ESP security association for %s: %w", spec.Name, err)
		}
		created = append(created, func() error { return netlink.XfrmStateDel(state) })
	}

	for _, outbound := range []bool{true, false} {
		dir := netlink.XFRM_DIR_OUT
		src, dst := local, remote
		spi := spec.EspSPIOut
		if !outbound {
			dir = netlink.XFRM_DIR_IN
			src, dst = remote, local
			spi = spec.EspSPIIn
		}
		policy := &netlink.XfrmPolicy{
			Src: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Dir: dir, Action: netlink.XFRM_POLICY_ALLOW, Ifid: ifid,
			Tmpls: []netlink.XfrmPolicyTmpl{{
				Dst: dst, Src: src, Proto: netlink.XFRM_PROTO_ESP,
				Mode: netlink.XFRM_MODE_TRANSPORT, Spi: int(spi), Reqid: ifid,
			}},
		}
		trace(ctx, fmt.Sprintf("XfrmPolicyAdd dir %s if_id %d", dir, ifid), nil)
		if err := netlink.XfrmPolicyAdd(policy); err != nil {
			cleanup()
			return i18n.Errorf(ctx, "adding the ESP policy for %s: %w", spec.Name, err)
		}
		created = append(created, func() error { return netlink.XfrmPolicyDel(policy) })
	}
	return nil
}

// deleteESP removes the states and policies bound to one interface
// identifier. The interface itself is deleted by the caller: the states and
// policies outlive it, so deleting the link alone would leave stale
// associations behind.
func deleteESP(ctx context.Context, ifid uint32) {
	deleteESPByIfID(ctx, int(ifid))
}

// deleteESPByIfID removes every XFRM state and policy bound to an interface
// identifier. Errors are swallowed: this runs during cleanup, where a
// missing association is the expected state, and a failure to remove one
// must not mask the error that triggered the cleanup.
func deleteESPByIfID(ctx context.Context, ifid int) {
	states, err := netlink.XfrmStateList(unix.AF_UNSPEC)
	if err == nil {
		for _, s := range states {
			if s.Ifid == ifid {
				_ = netlink.XfrmStateDel(&s)
			}
		}
	}
	policies, err := netlink.XfrmPolicyList(unix.AF_UNSPEC)
	if err == nil {
		for _, p := range policies {
			if p.Ifid == ifid {
				_ = netlink.XfrmPolicyDel(&p)
			}
		}
	}
}

// espReadback accumulates the kernel's XFRM facts for one interface
// identifier while a list is grouped.
type espReadback struct {
	attrs     *EspAttrs
	inPolicy  bool
	outPolicy bool
}

// espAttrsByIfID lists the kernel's XFRM states and policies once and
// groups them by interface identifier, so List can attach them to every
// xfrm interface in one pass.
func espAttrsByIfID() (map[uint32]*EspAttrs, error) {
	states, err := netlink.XfrmStateList(unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	policies, err := netlink.XfrmPolicyList(unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	byIfID := map[uint32]*espReadback{}
	for _, s := range states {
		if s.Ifid == 0 {
			continue
		}
		rb := byIfID[uint32(s.Ifid)]
		if rb == nil {
			rb = &espReadback{attrs: &EspAttrs{IfID: uint32(s.Ifid)}}
			byIfID[uint32(s.Ifid)] = rb
		}
		rb.attrs.SPIs = append(rb.attrs.SPIs, uint32(s.Spi))
	}
	for _, p := range policies {
		if p.Ifid == 0 {
			continue
		}
		rb := byIfID[uint32(p.Ifid)]
		if rb == nil {
			rb = &espReadback{attrs: &EspAttrs{IfID: uint32(p.Ifid)}}
			byIfID[uint32(p.Ifid)] = rb
		}
		switch p.Dir {
		case netlink.XFRM_DIR_IN:
			rb.inPolicy = true
		case netlink.XFRM_DIR_OUT:
			rb.outPolicy = true
		}
	}
	out := make(map[uint32]*EspAttrs, len(byIfID))
	for id, rb := range byIfID {
		sort.Slice(rb.attrs.SPIs, func(i, j int) bool { return rb.attrs.SPIs[i] < rb.attrs.SPIs[j] })
		rb.attrs.PoliciesPresent = rb.inPolicy && rb.outPolicy
		out[id] = rb.attrs
	}
	return out, nil
}

// espAttrsFor returns the readback for one interface identifier, or just the
// identifier itself when the kernel reported nothing for it — which is how
// verification sees a tunnel whose associations are missing.
func espAttrsFor(ifid uint32, byIfID map[uint32]*EspAttrs) *EspAttrs {
	if a, ok := byIfID[ifid]; ok {
		return a
	}
	return &EspAttrs{IfID: ifid}
}
