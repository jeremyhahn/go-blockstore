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
