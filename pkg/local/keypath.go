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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// ErrKeyFileInsideVolume reports a LUKS key file that lives inside a path this
// provider hands to a workload.
//
// The whole point of the privilege-separated deployment is that ONLY THE MOUNT
// crosses the boundary and never the key. A shared volume is exactly where
// somebody would think to put a key file, and if they do it WORKS: the volume
// unlocks, nothing errors, and the credential is published to the container
// that was specifically designed never to see it. Nothing downstream can detect
// that, because from the workload's side it is an ordinary file in its own
// filesystem.
var ErrKeyFileInsideVolume = errors.New("the LUKS key file is inside a path handed to the workload")

// ErrKeyFileUnresolvable reports a key path that could not be resolved to a
// real location, so containment could not be established.
//
// It fails closed. A path this provider cannot resolve is one it cannot prove
// is outside the volume, and "could not check" must not read as "checked and
// fine" for a credential — that is the same substitution the mount-propagation
// guard refuses one layer up.
var ErrKeyFileUnresolvable = errors.New("the LUKS key file path could not be resolved, so it cannot be shown to be outside the volume")

// resolveKeyFile turns the configured key path into the location a reader would
// actually reach.
//
// SYMLINKS ARE RESOLVED FIRST, and that is the point rather than tidiness. A key
// file reached through a symlink into the volume is the same exposure as one
// placed there directly, and a string comparison against the configured path
// misses it entirely — the configured path can be /etc/keys/vol.key while the
// bytes come from inside the volume the workload is about to receive.
//
// The file need not exist yet. A deployment can mount its key material after
// building the provider, so a missing file is resolved as far as its deepest
// existing ancestor and judged on that: a key file that does not exist yet in a
// directory inside the volume is the same exposure the moment it appears.
//
// WHAT THAT FALLBACK COSTS, AND WHY THE ANSWER IS NOT TO REMOVE IT. Resolving a
// missing leaf against its deepest existing ancestor means a path whose SYMLINK
// COMPONENT dangles is resolved lexically — the link is not followed, because
// following it lands on something that is not there. So /etc/keys ->
// /mnt/vol/keys, with /mnt/vol an empty mount point, resolves to the literal
// /etc/keys/vol.key and reads as outside the volume. Measured on this kernel:
// after mounting a filesystem carrying keys/vol.key at /mnt/vol, the SAME
// configured path resolves to /mnt/vol/keys/vol.key and reads the volume's own
// bytes, and it goes back to reading as outside after the unmount.
//
// That is not a direction of the predicate to correct. The information is not
// present before the mount, in either direction, and the fallback that hides it
// is load-bearing: refusing a key file that has not been placed yet breaks a
// legitimate deployment order. So this function stays as it is, and what
// changed is WHEN it is asked — see checkKeyFileAgainstMountedFilesystem.
func resolveKeyFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrKeyFileUnresolvable, path)
	}
	// A path that filepath.Clean would change is REFUSED rather than cleaned,
	// and that closes a bypass rather than tidying the input.
	//
	// Clean collapses "link/.." lexically, to the parent of the link. The kernel
	// does not: it follows the symlink and then goes up from its TARGET. So with
	// /keys/link -> /mnt/vol/dir, the configured /keys/link/../volume.key is
	// opened from /mnt/vol/volume.key while Clean says /keys/volume.key — the
	// guard would compare a location the reader never touches and allow a key
	// file sitting inside the volume.
	//
	// Emulating the kernel's resolution component by component is possible and
	// is the kind of thing that is subtly wrong for years. Refusing the input
	// removes the disagreement instead: with a clean path, Clean is a no-op and
	// cannot say something different from what os.Open will do. It is also the
	// rule every other path in this package already lives under — see
	// validateAbsPath.
	if filepath.Clean(path) != path {
		return "", fmt.Errorf("%w: %q is not a clean path; a key path must contain no %q, %q or trailing separator, "+
			"because those resolve differently through a symlink than they read",
			ErrKeyFileUnresolvable, path, "..", "//")
	}

	// Walk up to the deepest component that exists, resolving symlinks there,
	// then re-attach what was missing. EvalSymlinks refuses a path whose leaf
	// is absent, and refusing a key file that has not been placed yet would
	// break a legitimate deployment order.
	missing := ""
	current := filepath.Clean(path)
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			return filepath.Join(resolved, missing), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("%w: resolving %q: %w", ErrKeyFileUnresolvable, path, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			// Reached the root without finding anything that exists, which
			// cannot happen on a running system and is not a case to guess at.
			return "", fmt.Errorf("%w: nothing along %q exists", ErrKeyFileUnresolvable, path)
		}
		missing = filepath.Join(filepath.Base(current), missing)
		current = parent
	}
}

// withinPath reports whether the resolved path lies at or under the directory.
//
// Compared as path COMPONENTS rather than as strings: "/mnt/data" must not
// contain "/mnt/database", which a prefix test on the raw strings would say it
// does. Both sides are already resolved by the time this is asked.
func withinPath(resolved, dir string) bool {
	if resolved == "" || dir == "" {
		return false
	}
	resolved, dir = filepath.Clean(resolved), filepath.Clean(dir)
	if resolved == dir {
		return true
	}
	return strings.HasPrefix(resolved, dir+string(filepath.Separator))
}

// checkKeyFileOutside refuses a key file that lives inside the given path.
//
// The comparison is done on the RESOLVED key path and a resolved target, so a
// symlink on either side cannot hide the containment. A target that cannot be
// resolved is a refusal for the same reason an unresolvable key path is: the
// question was whether the credential is outside, and an unanswerable question
// is not a yes.
//
// Every answer it gives is about THE FILESYSTEM AS IT IS WHEN IT IS ASKED. That
// is not a caveat on the implementation, it is the property the callers are
// arranged around: asked before a mount it can refuse but it cannot approve,
// and asked after one it can do both. See checkKeyFileAgainstMountedFilesystem.
func (p *Provider) checkKeyFileOutside(target, why string) error {
	if p.keyFile == "" {
		return nil
	}

	key, err := resolveKeyFile(p.keyFile)
	if err != nil {
		return err
	}
	resolvedTarget, err := resolveKeyFile(target)
	if err != nil {
		return fmt.Errorf("%w: resolving %s %q: %w", ErrKeyFileUnresolvable, why, target, err)
	}

	if withinPath(key, resolvedTarget) {
		return fmt.Errorf("%w: %s resolves to %s, inside %s (%s); the mount crosses the boundary and the key must not: %w",
			common.ErrInvalidArgument, SettingLUKSKeyFile, key, resolvedTarget, why, ErrKeyFileInsideVolume)
	}
	return nil
}

// checkKeyFileOutsideOurVolumes refuses a key file that lives inside a path
// where ANY volume this provider manages is mounted.
//
// Every volume, not just the one being operated on, because the key file is
// PROVIDER-GLOBAL: one luks_key_file serves the whole volume group. A key
// stored inside volume A is readable by whoever consumes A, and that is true
// while this provider is attaching volume B — B's own devices are innocent and
// checking only them hands B over while A's workload reads the credential.
//
// It is the Mount check from the other side. Mount refuses a target that would
// come to contain the key; this refuses a key already inside a volume — the
// order a deployment reaches when the volume is mounted first and the key file
// written into it afterwards, which is what somebody does when the shared
// volume looks like a convenient place to keep it.
//
// A mount table that cannot be read is a refusal, not a pass. The question is
// whether a credential is exposed, and an unanswerable question about a
// credential is answered no.
// The caller passes the volume list it already holds. Both call sites — Mount
// and the attach path — have just read it, and re-reading would add an LVM exec
// to every one of those operations for nothing. What remains is /proc reads,
// which touch neither LVM nor udev.
func (p *Provider) checkKeyFileOutsideOurVolumes(ctx context.Context, lvs []lvInfo) error {
	if p.keyFile == "" {
		return nil
	}

	for i := range lvs {
		if lvs[i].isSnapshot() {
			continue
		}
		// BOTH devices, because which one carries the filesystem depends on
		// whether the volume is encrypted: a plaintext volume is mounted from
		// the logical volume, and an encrypted one from the plaintext MAPPING
		// over it. Looking only at the logical volume finds no mounts for
		// exactly the volumes this guard protects — measured, by an integration
		// test against a real encrypted volume that the check read as passing.
		for _, device := range []string{p.lvPath(lvs[i].Name), p.cryptPath(lvs[i].Name)} {
			mounts, err := p.mountpointsFor(ctx, device)
			if err != nil {
				// A device that is not there has no mounts to be inside of,
				// which is the ordinary case for whichever of the two a volume
				// is not using. Anything else is a table this provider could
				// not read.
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return fmt.Errorf("%w: checking whether %s is inside %q's mounts: %w",
					ErrKeyFileUnresolvable, SettingLUKSKeyFile, lvs[i].Name, err)
			}

			for _, target := range mounts {
				if err := p.checkKeyFileOutside(target, "a path volume "+lvs[i].Name+" is mounted at"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkKeyFileAgainstMountedFilesystem asks the containment question of the
// filesystem that is now actually mounted, and it is the guard's authority.
//
// A MOUNT SUBSTITUTES. It does not hide and it does not publish; it does both
// at once, and the two are one event seen from either side. Before the mount a
// path under the target reaches the HOST's file; after it, the same path
// reaches the VOLUME's file at that relative position, or nothing when the
// volume carries nothing there. Both were measured on this kernel.
//
// The checks that run before mount(2) predict that substitution. Three review
// rounds corrected the prediction in a new direction each time (#36, #48, and
// the review on #46 that raised #51), which is the shape of a wrong question
// rather than a wrong answer: one observation of a substitution always looks
// like a one-way effect, and each test was written from the model that produced
// it, so each locked in whichever half was in view.
//
// The case that settles it is not a direction at all. With /etc/keys a symlink
// to <target>/keys and <target> an empty mount point, resolveKeyFile CANNOT
// follow the link — its destination does not exist — so it resolves the key
// path lexically and reports it outside the volume. Mount a filesystem carrying
// keys/vol.key at the target and the same configured path resolves to
// <target>/keys/vol.key and reads the volume's own bytes. Measured against a
// live kernel; the test naming this function reproduces it with a real mount(2)
// in a user namespace. No correction to the predicate reaches that, because the
// pre-mount filesystem does not hold the answer, and the fallback that hides it
// is the one a deployment placing its key material later depends on.
//
// So the checks are split by what they are entitled to conclude:
//
//   - BEFORE the mount, checkKeyFileOutside may REFUSE and may not APPROVE. It
//     is a fail-fast that keeps the ordinary misconfiguration from ever
//     reaching mount(2), and its passing means only "not visibly wrong yet".
//   - AFTER the mount, this function DECIDES. Every path it resolves is on the
//     filesystem the workload will be handed, so there is nothing left to model.
//
// It re-asks BOTH questions, because the new mount can change either answer:
// the key path may now resolve into the volume just mounted at target, and it
// may equally now resolve — through a symlink the new mount just substituted —
// into some OTHER volume of this group's mount. The added cost is /proc reads
// and path resolution, on a path that has just performed a mount(2).
//
// A refusal here means the mount happened and must be undone; the caller
// unwinds it. The alternative considered was the one #51 proposed — mount into
// a private staging location, check there, then MS_MOVE to the target. It was
// measured rather than argued, and it is mechanically possible: a staging mount
// made outside the shared subtree is private, MS_MOVE into a shared parent
// succeeds, and the published mount comes out SHARED as the propagation guard
// requires. It was rejected because it answers a DIFFERENT QUESTION. Staging
// shows what the volume CONTAINS, not what the configured key path RESOLVES to
// — measured: with the volume mounted at staging, the case above still reports
// the key outside the target, which is the same wrong answer the prediction
// gives. Converting "the volume contains keys/vol.key" into "the configured
// path will resolve into the volume" is the prediction again, one step removed,
// and it is bought with an extra mount(2), an MS_MOVE that is EINVAL whenever
// the staging mount is shared, and a window with the volume mounted where the
// caller never asked for it.
func (p *Provider) checkKeyFileAgainstMountedFilesystem(ctx context.Context, target string, lvs []lvInfo) error {
	if p.keyFile == "" {
		return nil
	}

	// Detached from the caller's context, for the reason verifyMountPropagation
	// is: once mount(2) has returned, observing and — if the observation refuses
	// — unwinding are COMPLETION work. A caller whose deadline passed in that
	// instant would otherwise leave a mount nobody checked and nobody cleans up,
	// with a credential possibly inside it, because the reads that would find it
	// fail first.
	ctx, cancel := unwindContext(ctx)
	defer cancel()

	if err := p.checkKeyFileOutside(target, "the path this volume is now mounted on"); err != nil {
		return err
	}
	return p.checkKeyFileOutsideOurVolumes(ctx, lvs)
}

// unwindRefusedMount removes a mount the key-path observation refused.
//
// A Mount that returns an error must not leave a filesystem mounted, and that
// is sharper here than anywhere else in this provider: the reason for the
// refusal is that a workload reaching the target can read the volume group's
// unlock credential, so a mount left behind is the exposure itself, standing.
//
// It unmounts by PATH, which is all umount(2) takes, so it first confirms this
// volume is the filesystem VISIBLE there — the same test Unmount makes before
// the same syscall, and it is asked from the mount TREE rather than from
// mount-point strings, so an overmount of an ANCESTOR of the target counts as
// having taken it over. Without that, a rollback would detach whatever somebody
// else mounted over the target in the gap since mount(2) returned, over a
// cleanup of our own.
//
// It is separate from unwindUnverifiedMount, which asks the kernel's mount ID
// instead. That test is strictly stronger — it also catches a SECOND mount of
// the SAME device stacked on the target, which visibility cannot distinguish —
// but it needs the optional MountPropagationReader half of the mount-table
// seam. The propagation guard may require that, because a caller who turned the
// propagation policy on is refused at construction without it. This guard runs
// under EVERY propagation policy, including the default, so it cannot require
// an optional method; it uses the strongest test the mandatory interface can
// answer and leaves the residue named here rather than unremarked.
//
// The finding is what the caller gets back either way. A failed rollback is
// joined onto it rather than replacing it: the credential exposure is the
// finding, what happened to the cleanup is a second fact about the same event,
// and an operator needs both — and needs to be told first about the one that is
// still true.
func (p *Provider) unwindRefusedMount(ctx context.Context, device, target string, finding error) error {
	ctx, cancel := unwindContext(ctx)
	defer cancel()

	visible, err := p.visibleMountpointsFor(ctx, device)
	if err != nil {
		return errors.Join(finding, err)
	}
	if !contains(visible, target) {
		return errors.Join(finding, errUnwindTargetTakenOver)
	}
	if err := p.umount(ctx, target); err != nil {
		return errors.Join(finding, err)
	}
	return finding
}
