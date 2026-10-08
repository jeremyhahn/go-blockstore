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

package local

import (
	"context"
	"errors"
	"strconv"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-blockstore/internal/luks"
)

// errScope attributes this package's LUKS failures to it.
//
// The machinery underneath is shared with pkg/drbd, so the message an operator
// reads has to say which provider produced it — "unlocking /dev/vg0/data" is a
// different investigation depending on whether a logical volume or a replicated
// device is on the other end of it.
const errScope = "go-blockstore/local"

// fsTypeLUKS is what blkid reports for a LUKS container.
const fsTypeLUKS = luks.FSType

// luksHeaderBytes is the space a LUKS2 container this provider formats reserves
// in front of the caller's data. See internal/luks.HeaderBytes for the
// derivation and what it is measured against.
const luksHeaderBytes = luks.HeaderBytes

// mappingPrefix namespaces this provider's device-mapper names so an unlocked
// volume is recognizable on a host that also runs other LUKS consumers —
// pkg/drbd included, which is why the two prefixes are declared together.
const mappingPrefix = luks.MappingPrefix

// luksBackend is the seam between this provider and the LUKS2 implementation
// underneath it. See internal/luks.Backend.
//
// It stays an alias rather than becoming a plain reference so that Options.luks
// — the unexported seam the tests fill — keeps naming a type this package
// declares.
type luksBackend = luks.Backend

// mappingInfo describes an open device-mapper mapping. See internal/luks.
type mappingInfo = luks.MappingInfo

// KeyProvider supplies the passphrase that unlocks a volume's LUKS container,
// as a locked enclave rather than as bytes. See internal/luks.KeyProvider for
// the ownership rules, the borrow window and the size bounds.
type KeyProvider = luks.KeyProvider

// FileKeyProvider returns a KeyProvider that reads the passphrase from a file,
// re-reading it on each call so a rotated key file takes effect without
// restarting the process.
func FileKeyProvider(path string) KeyProvider { return luks.FileKeyProvider(errScope, path) }

// StaticKeyProvider returns a KeyProvider backed by a fixed passphrase, held in
// the enclave it is given for the returned provider's lifetime. It TAKES
// OWNERSHIP of stored.
func StaticKeyProvider(stored *enclave.MemoryEnclave) (KeyProvider, error) {
	return luks.StaticKeyProvider(errScope, stored)
}

// encryptedTagPrefix names the LVM tag this provider sets on a volume once it
// holds a LUKS container, and the tag CARRIES THE HEADER'S SIZE rather than
// just the fact that there is one: "blockstore.luks-header=16777216".
//
// It exists for one question: what is a DETACHED volume's usable capacity?
// Answering it means knowing what the volume's header costs, and an inactive
// logical volume has no device node to read one from — measured, blkid answers
// a path that does not exist with the same "nothing here" status it uses for a
// device carrying no signature, so probing one reports every encrypted volume
// as plain. Status holds no lock and must not activate a volume to look.
//
// The SIZE is in the tag, and not merely a boolean, because the size is known
// at every point one is written and is not recoverable later. A volume restored
// verbatim from an outside snapshot carries THAT snapshot's header, which need
// not be the 16 MiB this package formats — the restore measured it to size the
// volume, so recording only "encrypted" would throw away a number already in
// hand and leave Status subtracting the wrong one. That error does not stay
// small or stay safe: against a 32 MiB header it OVER-states usable capacity by
// 16 MiB, and a caller sizing data to the answer would overrun the volume.
//
// The name is dot-namespaced and spelled out. A volume group is a shared place
// — the same reasoning that makes this provider check a device-mapper name's
// backing device rather than trust the name — so the tag has to be one no
// operator or neighboring tool would pick by accident, and it has to mean
// something to a human reading `lvs -o lv_tags` on a group they did not set up.
// Measured on LVM 2.03.16: every character here is in the set LVM accepts, "="
// included; the tag round-trips through the JSON report verbatim; --addtag and
// --deltag are both idempotent; and --deltag and --addtag can be given to one
// lvchange, which is what lets the value be corrected atomically.
//
// Tags are NOT inherited by snapshots — measured: a snapshot of a tagged origin
// comes back with no tags at all — so nothing here decides anything about a
// snapshot. A restore reads the source's header off the snapshot device
// instead, which it has activated anyway.
const encryptedTagPrefix = "blockstore.luks-header="

// encryptedTagFor renders the tag recording a container's header size.
func encryptedTagFor(headerBytes int64) string {
	return encryptedTagPrefix + strconv.FormatInt(headerBytes, 10)
}

// ErrResizeWhileAttached is returned by Resize for an encrypted volume whose
// plaintext mapping is open on this node. Detach it and resize again.
//
// It exists because growing a dm-crypt mapping in place means reloading the
// device-mapper table underneath the live device, and that needs the
// container's master key. go-luks2 v1.0.0-rc.2 exposes no resize and no table
// reload (pkg/dmcrypt has Activate, Lookup and Deactivate), so the only
// mechanism available through it is to REMOVE the mapping and unlock again. That is a destructive shape wearing a resize's name: the
// teardown is unconditional and the rebuild can fail — a KeyProvider rotated
// since the volume was attached, a damaged header, any device-mapper refusal —
// and what the caller is left with is not an unresized volume but no plaintext
// device at all. Validating the key first narrows the window and does not close
// it, so the operation is refused rather than attempted.
//
// It is NOT wrapped around common.ErrUnsupported, and the difference is the
// whole value of the sentinel. ErrUnsupported tells a caller this backend
// cannot serve the request and that retrying or reconfiguring is pointless;
// this request is served perfectly well one Detach later, which is the opposite
// advice. A caller holding the attachment acts on that distinction — it is the
// same shape as common.ErrNotPrimary, "the request is fine, the volume is in
// the wrong state at the moment" — so the sentinel says so in its own right.
//
// The detached path has no such hazard and is not restricted: Resize over a
// detached volume unlocks the container itself, grows the filesystem and locks
// it again, and a failure anywhere in that leaves the volume exactly as
// detached as it started. See growDetachedEncryptedFilesystem.
var ErrResizeWhileAttached = errors.New("cannot resize an encrypted volume while it is attached")

// -----------------------------------------------------------------------------
// The provider's view of the shared machinery
//
// Every method below delegates to internal/luks.Manager, which holds the pinned
// cryptographic parameters, the passphrase borrow window and the mapping
// ownership check. What stays here is the one thing that is this provider's:
// the backing device a mapping is expected to be over is a logical volume.
// -----------------------------------------------------------------------------

// mappingName is the device-mapper name an unlocked volume appears under.
func (p *Provider) mappingName(volID string) string { return p.crypt.MappingName(volID) }

// cryptPath is the device path of an unlocked volume's plaintext mapping.
func (p *Provider) cryptPath(volID string) string { return p.crypt.CryptPath(volID) }

// luksFormat writes a LUKS2 header onto the device.
func (p *Provider) luksFormat(ctx context.Context, volID, device string) error {
	return p.crypt.Format(ctx, volID, device)
}

// luksOpen unlocks the container and exposes its plaintext mapping.
func (p *Provider) luksOpen(ctx context.Context, volID, device string) error {
	return p.crypt.Open(ctx, volID, device)
}

// luksClose tears down the plaintext mapping.
func (p *Provider) luksClose(ctx context.Context, volID string) error {
	return p.crypt.Close(ctx, volID)
}

// luksTestPassphrase checks that the key this provider holds for volID opens
// the container on device, WITHOUT unlocking it.
func (p *Provider) luksTestPassphrase(ctx context.Context, volID, device string) error {
	return p.crypt.TestPassphrase(ctx, volID, device)
}

// luksDataOffset reports where a container's data starts — the space its header
// occupies, and so the difference between the logical volume's size and the
// usable capacity of the mapping over it.
func (p *Provider) luksDataOffset(ctx context.Context, device string) (int64, error) {
	return p.crypt.DataOffset(ctx, device)
}

// luksIsOpen reports whether the volume's plaintext mapping exists AND is the
// one this provider would have made — over THIS volume's logical volume, which
// is what the name alone does not establish.
func (p *Provider) luksIsOpen(ctx context.Context, volID string) (bool, error) {
	return p.crypt.IsOpen(ctx, volID, p.lvPath(volID))
}
