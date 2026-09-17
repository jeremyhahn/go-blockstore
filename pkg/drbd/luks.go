// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-blockstore.
//
// go-blockstore is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build drbd

package drbd

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// errScope attributes this package's LUKS failures to it.
//
// The machinery underneath is shared with pkg/local, so the message an operator
// reads has to say which provider produced it: "unlocking /dev/drbd7" is a
// different investigation from "unlocking /dev/vg0/data".
const errScope = "go-blockstore/drbd"

// fsTypeLUKS is what blkid reports for a LUKS container.
const fsTypeLUKS = luks.FSType

// ErrResizeEncrypted is returned by Resize, and by a restore that would have to
// grow its destination, on a provider configured to encrypt.
//
// The dm-crypt mapping over /dev/drbdN is sized from the replicated device AT
// THE MOMENT Promote opens it, and go-luks2 exposes no table reload. So after a
// drbdadm resize the plaintext device is still the size it was when it was
// unlocked, and the filesystem inside it cannot be grown to the new size while
// the container is open. Growing the device anyway and recording the new size
// would report a resize as complete over a filesystem that had not moved — the
// silent wrong answer this package refuses to give — so the whole operation is
// refused instead, before anything is extended.
//
// It wraps common.ErrUnsupported, and that is the right portable reading: the
// request is well-formed, this backend cannot serve it as configured, and no
// retry or demote/promote cycle changes the answer. pkg/local's counterpart,
// ErrResizeWhileAttached, deliberately does NOT wrap ErrUnsupported because
// there one Detach lifts the refusal; here nothing the caller does lifts it.
// What lifts it is issue #62 — sizing the container from a header on top and a
// grow that knows about the mapping — which builds on this revision.
var ErrResizeEncrypted = fmt.Errorf("%w: an encrypted volume cannot be resized by this revision — the dm-crypt mapping is sized when Promote opens it and go-luks2 exposes no reload, so the filesystem cannot be grown to the new size while the container is open (tracked by issue #62)", common.ErrUnsupported)

// KeyProvider supplies the passphrase that unlocks a volume's LUKS container,
// as a locked enclave rather than as bytes. See internal/luks.KeyProvider for
// the ownership rules, the borrow window and the size bounds.
type KeyProvider = luks.KeyProvider

// FileKeyProvider returns a KeyProvider that reads the passphrase from a file,
// re-reading it on each call so a rotated key file takes effect without
// restarting the process. It is what luks_key_file installs.
func FileKeyProvider(path string) KeyProvider { return luks.FileKeyProvider(errScope, path) }

// StaticKeyProvider returns a KeyProvider backed by a fixed passphrase, held in
// the enclave it is given for the returned provider's lifetime. It TAKES
// OWNERSHIP of stored.
func StaticKeyProvider(stored *enclave.MemoryEnclave) (KeyProvider, error) {
	return luks.StaticKeyProvider(errScope, stored)
}

// WithKeyProvider supplies the passphrase that unlocks the LUKS container over
// each replicated device. It takes precedence over luks_key_file.
//
// It is the same arrangement WithSecretProvider is, and for the same reason: a
// caller holding the key somewhere this package should not know about — a
// TPM-sealed blob, an operator prompt, a KMS — unseals it into an enclave and
// hands it over here.
//
// The two secrets are NOT interchangeable and must not be the same material.
// The replication secret authenticates the peer and is known to both nodes'
// DRBD; this one decrypts the volume. A deployment that fed one file to both
// would have given its peer-authentication secret the job of protecting the
// data as well.
func WithKeyProvider(k KeyProvider) Option {
	return func(p *Provider) { p.keyProvider = k }
}

// withLUKSBackend replaces the LUKS2 implementation. Tests use it to drive the
// whole provider without device-mapper or a real container.
//
// It is unexported, unlike WithRunner and WithMounter, because it is not a seam
// a caller has any business filling. Those two exist for callers as much as for
// tests — a deployment can legitimately want its own exec or mount
// implementation — while an outside implementation of this one would be an
// outside implementation of the encryption, which is exactly the thing this
// package pins rather than delegates.
func withLUKSBackend(b luks.Backend) Option {
	return func(p *Provider) { p.luks = b; p.injected.luks = true }
}

// ErrNotUnlocked reports an encrypted volume whose plaintext mapping is not
// open on this node.
//
// It is its own sentinel because the advice it carries is specific: the volume
// is fine and the node is fine, and what is missing is a Promote. The container
// is opened there — see Promote — so an operation that needs the plaintext
// device on a node that has not promoted is asking too early rather than asking
// for something impossible.
//
// It is NOT reported as a pass. An encrypted volume whose crypt state cannot be
// established is refused, on the reasoning pkg/preflight states for the same
// shape: a condition that could not be verified is reported as a failure rather
// than assumed to be fine.
var ErrNotUnlocked = errors.New("the volume's LUKS container is not open on this node")

// mappingNamespace is what a mapping name carries in front of the volume ID.
//
// The SEPARATOR is a dot and not the underscore pkg/local uses, and the
// difference is not cosmetic: a DRBD resource name may contain underscores —
// validateName's regexp allows them, because DRBD does — so scoping with one
// would let a volume group and a volume ID trade a character and spell the same
// mapping name as a different pair. A dot is rejected by that regexp in both
// positions, which makes the concatenation unambiguous.
//
// See internal/luks for why the prefix differs from pkg/local's as well.
func (p *Provider) mappingNamespace() string {
	return luks.ReplicatedMappingPrefix + p.cfg.VG + "."
}

// fsDevice is the device a volume's filesystem lives on.
//
// It is the plaintext mapping for an encrypted volume and the DRBD device for a
// plain one, and every step that touches the filesystem goes through it rather
// than spelling devicePath: the probe, the mkfs, the mount, the mount-table
// lookups and the grow. Mixing the two is the mistake this exists to prevent —
// a mkfs against /dev/drbdN on an encrypted volume would write a filesystem
// over the LUKS header, which is the one write that destroys the container and
// everything in it.
//
// The DEVICE-level operations keep spelling devicePath deliberately: the LUKS
// container is formatted onto /dev/drbdN, the wipe goes over the backing
// logical volume, and drbdadm resize grows the replicated device. Encryption
// sits above the replication, so those are the layer underneath it.
func (p *Provider) fsDevice(meta *resourceMeta) string {
	if !p.cfg.Encrypted {
		return devicePath(meta.Minor)
	}
	return p.crypt.CryptPath(meta.Name)
}

// containerIsOpen reports whether this volume's plaintext mapping is open and is
// the one this provider would have made — over THIS volume's DRBD device, which
// is what the name alone does not establish.
func (p *Provider) containerIsOpen(ctx context.Context, meta *resourceMeta) (bool, error) {
	return p.crypt.IsOpen(ctx, meta.Name, devicePath(meta.Minor))
}

// requireContainerOpen refuses an operation that needs the plaintext device on a
// volume whose container is not open.
//
// It is a separate check from requirePrimary rather than an inference from it.
// Promote opens the container, so a Primary node ordinarily has one — but
// "ordinarily" is not a guarantee: a node promoted before this provider was
// configured for encryption, an operator who closed the mapping by hand, or a
// promotion whose open failed and left the role behind all reach here Primary
// with nothing to mount. Reading the role as proof of the mapping would then
// hand mount(2) a device node that does not exist, and the error it returns
// says nothing about what is actually wrong.
func (p *Provider) requireContainerOpen(ctx context.Context, meta *resourceMeta) error {
	if !p.cfg.Encrypted {
		return nil
	}
	open, err := p.containerIsOpen(ctx, meta)
	if err != nil {
		return err
	}
	if !open {
		return fmt.Errorf("volume %q: promote it on this node to unlock it: %w", meta.Name, ErrNotUnlocked)
	}
	return nil
}

// openContainer unlocks the volume's LUKS container over the replicated device,
// formatting one first if the device carries nothing at all.
//
// IT RUNS FROM Promote AND NOWHERE ELSE, and the placement is the whole design.
// DRBD refuses every open of a Secondary's device — read-only opens included —
// so there is no earlier point at which a container over /dev/drbdN can be
// formatted or unlocked, and the measured crypt lifecycle in pkg/local puts the
// unlock at the layer that makes a device usable rather than at the mount:
// counted against its fake, Attach performs the container probe and the unlock
// and Mount performs neither. Promote is this provider's counterpart of that
// layer, since it is the transition that makes the device openable at all.
//
// THE FORMAT IS THE FIRST PROMOTE'S, and it is guarded the way this package
// already guards the mkfs in ensureFilesystem: only a device blkid reports as
// carrying NOTHING AT ALL is formatted, and any other answer — a failed probe
// included — leaves the device untouched. A volume that already holds a
// container is unlocked instead, which is what every failover after the first
// does: the header replicated with the data, so the new Primary opens the
// container its peer wrote.
//
// A device carrying something that is NOT a LUKS container is refused rather
// than formatted over. That is a volume provisioned before encryption was
// configured, and turning it into a container would destroy the filesystem on
// it; the refusal names what was found so the operator can decide.
func (p *Provider) openContainer(ctx context.Context, meta *resourceMeta) error {
	if !p.cfg.Encrypted {
		return nil
	}
	dev := devicePath(meta.Minor)

	open, err := p.containerIsOpen(ctx, meta)
	if err != nil {
		return err
	}
	if open {
		// Already unlocked — a repeated Promote, or a role this node held
		// before the call. Opening again would be an error from
		// device-mapper, and the caller's request is already satisfied.
		return nil
	}

	found, empty, err := p.probeDevice(ctx, dev)
	if err != nil {
		return err
	}
	switch {
	case empty:
		if err := p.crypt.Format(ctx, meta.Name, dev); err != nil {
			return err
		}
	case found == fsTypeLUKS:
		// The container is there: this node is taking over a volume its peer
		// formatted, or its own after a demote.
	default:
		return fmt.Errorf("%w: volume %q is configured encrypted but %s carries %s; "+
			"this provider will not format a container over it",
			common.ErrInvalidArgument, meta.Name, dev, describeSignature(found))
	}

	return p.crypt.Open(ctx, meta.Name, dev)
}

// closeContainer tears down the volume's plaintext mapping if it has one.
//
// IT RUNS BEFORE EVERY STATE CHANGE THAT NEEDS THE DEVICE FREE — the demotion,
// the resource-down in Detach and the one in Delete — and the ordering is not
// stylistic. An open dm-crypt mapping holds /dev/drbdN open, and DRBD refuses
// to demote or take down a device somebody has open; leaving the close until
// afterwards would make every one of those operations fail on a busy device and
// report it as if the volume were in use by a workload.
//
// It converges. A volume with no mapping, or one already closed, is not an
// error — a teardown path can call this without first working out how far setup
// got. What is NOT tolerated is a mapping this provider cannot identify: that
// comes back from containerIsOpen as an error and stops the teardown, because
// the alternative is closing somebody else's mapping.
func (p *Provider) closeContainer(ctx context.Context, meta *resourceMeta) error {
	if !p.cfg.Encrypted {
		return nil
	}
	open, err := p.containerIsOpen(ctx, meta)
	if err != nil {
		return err
	}
	if !open {
		return nil
	}
	return p.crypt.Close(ctx, meta.Name)
}

// describeSignature renders what blkid found on a device for an error a human
// has to act on. blkid reports the empty string for a device it recognized
// something on without naming a filesystem type — a partition table, say — and
// "a " in front of nothing reads as a bug in the message.
func describeSignature(fsType string) string {
	if fsType == "" {
		return "a signature this provider does not recognize"
	}
	return "a " + fsType + " filesystem"
}
