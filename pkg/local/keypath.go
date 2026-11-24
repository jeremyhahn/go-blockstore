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

	"github.com/jeremyhahn/go-blockstore/internal/mountguard"
	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// ErrKeyFileInsideVolume reports a LUKS key file inside a path this provider hands to a workload.
var ErrKeyFileInsideVolume = errors.New("the LUKS key file is inside a path handed to the workload")

// ErrKeyFileUnresolvable reports a key path that could not be resolved, so containment is refused.
var ErrKeyFileUnresolvable = errors.New("the LUKS key file path could not be resolved, so it cannot be shown to be outside the volume")

// resolveKeyFile resolves symlinks in the key path, resolving a missing file against its deepest existing ancestor; see checkKeyFileAgainstMountedFilesystem.
func resolveKeyFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrKeyFileUnresolvable, path)
	}
	// A path filepath.Clean would change is refused, since the kernel resolves "link/.." from the link's target.
	if filepath.Clean(path) != path {
		return "", fmt.Errorf("%w: %q is not a clean path; a key path must contain no %q, %q or trailing separator, "+
			"because those resolve differently through a symlink than they read",
			ErrKeyFileUnresolvable, path, "..", "//")
	}

	// Resolve the deepest existing ancestor, then re-attach the missing components.
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

// withinPath reports whether the resolved path lies at or under dir, by path components.
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

// checkKeyFileOutside refuses a key file inside the resolved target; before a mount it can refuse but not approve.
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

// checkKeyFileOutsideOurVolumes refuses a key file inside any mounted volume of this group, using the caller's volume list; an unreadable mount table refuses.
func (p *Provider) checkKeyFileOutsideOurVolumes(ctx context.Context, lvs []lvInfo) error {
	if p.keyFile == "" {
		return nil
	}

	for i := range lvs {
		if lvs[i].isSnapshot() {
			continue
		}
		// Both devices: an encrypted volume is mounted from its plaintext mapping.
		for _, device := range []string{p.lvPath(lvs[i].Name), p.cryptPath(lvs[i].Name)} {
			mounts, err := p.mountpointsFor(ctx, device)
			if err != nil {
				// A missing device has no mounts; any other error is an unreadable table.
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

// checkKeyFileAgainstMountedFilesystem re-asks both containment questions after mount(2), and is the guard's authority; the caller unwinds a refused mount.
func (p *Provider) checkKeyFileAgainstMountedFilesystem(ctx context.Context, target string, lvs []lvInfo) error {
	if p.keyFile == "" {
		return nil
	}

	// Detached from the caller's context: checking and unwinding are completion work after mount(2).
	ctx, cancel := mountguard.UnwindContext(ctx)
	defer cancel()

	if err := p.checkKeyFileOutside(target, "the path this volume is now mounted on"); err != nil {
		return err
	}
	return p.checkKeyFileOutsideOurVolumes(ctx, lvs)
}

// unwindRefusedMount unmounts a refused mount only if this volume is visible at the target, joining any rollback failure onto the finding.
func (p *Provider) unwindRefusedMount(ctx context.Context, device, target string, finding error) error {
	ctx, cancel := mountguard.UnwindContext(ctx)
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
