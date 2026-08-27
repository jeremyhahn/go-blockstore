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

//go:build drbd && drbd_integration

// This file exercises the provider against a real DRBD 9 pair. It is selected
// by build tag rather than skipped at runtime, so an ordinary "go test -tags
// drbd" never compiles it and cannot accidentally run destructive operations
// against a node's storage:
//
//	go test -tags 'drbd drbd_integration' ./pkg/drbd/ -run Integration -v
//
// Both tags are needed. pkg/drbd's implementation files carry //go:build drbd,
// so building with drbd_integration alone would compile an empty package and
// this file would have nothing to test.
//
// It must run as root on a node with drbd-utils, the DRBD 9 kernel module and
// LVM, whose peer is reachable on the replication address and running the same
// resource configuration. It creates, formats, snapshots and destroys volumes
// in the configured volume group.

package drbd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-blockstore/pkg/common"
)

// Environment the harness reads. Everything except the acknowledgement maps
// onto a provider setting.
const (
	envVG          = "GO_BLOCKSTORE_DRBD_VG"
	envNode        = "GO_BLOCKSTORE_DRBD_NODE"
	envNodeAddr    = "GO_BLOCKSTORE_DRBD_NODE_ADDRESS"
	envPeer        = "GO_BLOCKSTORE_DRBD_PEER"
	envPeerAddr    = "GO_BLOCKSTORE_DRBD_PEER_ADDRESS"
	envConfigDir   = "GO_BLOCKSTORE_DRBD_CONFIG_DIR"
	envStateDir    = "GO_BLOCKSTORE_DRBD_STATE_DIR"
	envSecretFile  = "GO_BLOCKSTORE_DRBD_SECRET_FILE"
	envDestructive = "GO_BLOCKSTORE_DRBD_ALLOW_DESTRUCTIVE"
)

// integrationVolume is the volume name the harness creates and destroys. It is
// distinctive so that a leftover from an interrupted run is recognisable.
const integrationVolume = "gobs-integration"

const integrationSize = int64(256) << 20 // 256 MiB: small enough to sync quickly.

// integrationConfig builds the settings map from the environment. A missing
// variable fails rather than skips: the build tag is what selects this file, so
// having been compiled in, it was meant to run.
func integrationConfig(t *testing.T) map[string]string {
	t.Helper()

	if os.Getenv(envDestructive) != "1" {
		t.Fatalf("%s must be set to 1: this test creates and destroys logical volumes and DRBD resources on this node", envDestructive)
	}
	if os.Geteuid() != 0 {
		t.Fatal("the integration test must run as root: drbdadm and the LVM tools require it")
	}

	settings := map[string]string{}
	for env, setting := range map[string]string{
		envVG:         SettingVolumeGroup,
		envNode:       SettingNodeName,
		envNodeAddr:   SettingNodeAddress,
		envPeer:       SettingPeerNode,
		envPeerAddr:   SettingPeerAddress,
		envConfigDir:  SettingConfigDir,
		envStateDir:   SettingStateDir,
		envSecretFile: SettingReplicationSecretFile,
	} {
		if v := os.Getenv(env); v != "" {
			settings[setting] = v
		}
	}
	for _, required := range []string{SettingVolumeGroup, SettingNodeAddress, SettingPeerNode, SettingPeerAddress} {
		if settings[required] == "" {
			t.Fatalf("setting %q is required: set the matching GO_BLOCKSTORE_DRBD_* variable", required)
		}
	}
	// Peer authentication is required unless acknowledged, and BOTH nodes need
	// the same secret for a resource — which is a property of the pair this
	// harness cannot check from one side.
	if settings[SettingReplicationSecretFile] == "" {
		t.Fatalf("%s is required: set %s to a file holding the shared secret, the SAME secret on both nodes",
			SettingReplicationSecretFile, envSecretFile)
	}
	return settings
}

func newIntegrationProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(integrationConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// initialSync makes the local copy authoritative for the first time.
//
// The provider deliberately does not do this — see the package doc on initial
// sync and on force-primary — so the harness does it the way an operator would,
// which is also a demonstration of where the boundary sits.
func initialSync(t *testing.T, res string) {
	t.Helper()
	cmd := exec.Command("drbdadm", "--", "--overwrite-data-of-peer", "primary", res)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("initial sync of %q: %v: %s", res, err, out)
	}
}

func TestIntegrationVolumeLifecycle(t *testing.T) {
	p := newIntegrationProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	spec := common.VolumeSpec{
		Name:      integrationVolume,
		SizeBytes: integrationSize,
		FSType:    "ext4",
		Replicas:  2,
		Labels:    map[string]string{"suite": "integration"},
	}

	vol, err := p.Provision(ctx, spec)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() {
		// Best effort: the volume may already be gone if the test got that far.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = p.Demote(cleanupCtx, vol.ID)
		if err := p.Delete(cleanupCtx, vol.ID); err != nil && !errors.Is(err, common.ErrNotFound) {
			t.Logf("cleanup of %q: %v", vol.ID, err)
		}
	})

	// A freshly provisioned resource is up, Secondary and Inconsistent.
	st, err := p.Status(ctx, vol.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != common.VolumeStateAttached {
		t.Errorf("State after Provision = %q, want attached", st.State)
	}
	if st.SizeBytes < integrationSize {
		t.Errorf("SizeBytes = %d, want at least %d", st.SizeBytes, integrationSize)
	}

	// Promotion is refused until the copies agree, and the provider must not
	// paper over that with a force.
	if err := p.Promote(ctx, vol.ID); err == nil {
		t.Error("Promote of an Inconsistent volume succeeded; the provider must not force it")
	}

	initialSync(t, vol.ID)
	waitFor(t, ctx, p, vol.ID, common.ReplStateUpToDate, 5*time.Minute)

	if err := p.Promote(ctx, vol.ID); err != nil {
		t.Fatalf("Promote after sync: %v", err)
	}
	state, err := p.ReplicationState(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ReplicationState: %v", err)
	}
	if state.Role != common.ReplRolePrimary {
		t.Errorf("Role after Promote = %q, want primary", state.Role)
	}

	// Mount, write, read back.
	target := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("creating mount point: %v", err)
	}
	if err := p.Mount(ctx, vol.ID, target, common.MountOptions{Flags: []string{"noatime"}}); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	payload := []byte("go-blockstore drbd integration\n")
	file := filepath.Join(target, "canary")
	if err := os.WriteFile(file, payload, 0o644); err != nil {
		t.Fatalf("writing to the mounted volume: %v", err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("read back %q, want %q", got, payload)
	}

	if st, err := p.Status(ctx, vol.ID); err != nil {
		t.Fatalf("Status: %v", err)
	} else if st.State != common.VolumeStateMounted {
		t.Errorf("State while mounted = %q, want mounted", st.State)
	}

	// Snapshots work on the Primary.
	snapID, err := p.Snapshot(ctx, vol.ID, "canary")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snaps, err := p.ListSnapshots(ctx, vol.ID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 || snaps[0].ID != snapID {
		t.Fatalf("ListSnapshots = %+v, want just %q", snaps, snapID)
	}

	// A volume with snapshots is not deletable.
	if err := p.Delete(ctx, vol.ID); !errors.Is(err, common.ErrHasSnapshots) {
		t.Errorf("Delete with a snapshot = %v, want common.ErrHasSnapshots", err)
	}

	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	// Unmounting twice converges.
	if err := p.Unmount(ctx, vol.ID, target); err != nil {
		t.Errorf("second Unmount = %v, want nil", err)
	}

	// A larger restore, on real DRBD. The unit tests script every command; only
	// a real pair settles whether drbdadm resize accepts a Secondary, which is
	// the state a freshly restored volume is in.
	larger := integrationSize * 2
	restored, err := p.Provision(ctx, common.VolumeSpec{
		Name: integrationVolume + "-restored", SizeBytes: larger, Replicas: 2,
		SourceSnapshotID: snapID,
	})
	if err != nil {
		t.Fatalf("restoring into a larger volume: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := p.Delete(cleanupCtx, restored.ID); err != nil && !errors.Is(err, common.ErrNotFound) {
			t.Logf("cleanup of %q: %v", restored.ID, err)
		}
	})
	if st, err := p.Status(ctx, restored.ID); err != nil {
		t.Fatalf("Status of the restored volume: %v", err)
	} else if st.SizeBytes < larger {
		t.Errorf("restored volume is %d bytes, want at least the requested %d", st.SizeBytes, larger)
	}
	// The restored volume must be deleted before its source snapshot, since
	// Delete refuses a volume that still has snapshots and this one has none.
	if err := p.Delete(ctx, restored.ID); err != nil {
		t.Fatalf("deleting the restored volume: %v", err)
	}

	if err := p.DeleteSnapshot(ctx, snapID); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if err := p.DeleteSnapshot(ctx, snapID); !errors.Is(err, common.ErrSnapshotNotFound) {
		t.Errorf("second DeleteSnapshot = %v, want ErrSnapshotNotFound", err)
	}

	// Deleting requires demoting first.
	if err := p.Delete(ctx, vol.ID); !errors.Is(err, ErrPrimary) {
		t.Errorf("Delete while Primary = %v, want ErrPrimary", err)
	}
	if err := p.Demote(ctx, vol.ID); err != nil {
		t.Fatalf("Demote: %v", err)
	}
	if err := p.Delete(ctx, vol.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Status(ctx, vol.ID); !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Status after Delete = %v, want ErrNotFound", err)
	}
}

// TestIntegrationSnapshotRefusedOnSecondary checks the crash-consistency rule
// against a real resource rather than a scripted status.
func TestIntegrationSnapshotRefusedOnSecondary(t *testing.T) {
	p := newIntegrationProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	vol, err := p.Provision(ctx, common.VolumeSpec{Name: integrationVolume + "-sec", SizeBytes: integrationSize, Replicas: 2})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := p.Delete(cleanupCtx, vol.ID); err != nil && !errors.Is(err, common.ErrNotFound) {
			t.Logf("cleanup of %q: %v", vol.ID, err)
		}
	})

	if _, err := p.Snapshot(ctx, vol.ID, "nope"); !errors.Is(err, common.ErrNotPrimary) {
		t.Fatalf("Snapshot on a Secondary = %v, want common.ErrNotPrimary", err)
	}
}

// waitFor polls until the volume reaches the wanted connection state.
func waitFor(t *testing.T, ctx context.Context, p *Provider, volID string, want common.ReplConnState, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last common.ReplState
	for time.Now().Before(deadline) {
		state, err := p.ReplicationState(ctx, volID)
		if err != nil {
			t.Fatalf("ReplicationState: %v", err)
		}
		last = state
		if state.Conn == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %q: %v", want, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatalf("volume %q did not reach %q within %s; last state was %+v (peer %s)",
		volID, want, timeout, last, strings.TrimSpace(string(last.Peer)))
}

// TestIntegrationGeneratedConfigParses is the check no unit test can make: that
// what this package writes is something drbdadm actually accepts.
//
// The rendering tests assert on shape — balanced braces, one resource block, a
// secret that stayed inside its quotes — which catches injection but not a
// keyword this DRBD version spells differently or does not have. Only the
// parser settles that, and only where drbdadm is installed.
//
// sh-nop asks drbdadm to parse the configuration and do nothing, which needs no
// kernel module and changes nothing.
func TestIntegrationGeneratedConfigParses(t *testing.T) {
	p := newIntegrationProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	vol, err := p.Provision(ctx, common.VolumeSpec{
		Name: integrationVolume + "-parse", SizeBytes: integrationSize, Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := p.Delete(cleanupCtx, vol.ID); err != nil && !errors.Is(err, common.ErrNotFound) {
			t.Logf("cleanup of %q: %v", vol.ID, err)
		}
	})

	out, err := exec.Command("drbdadm", "sh-nop", vol.ID).CombinedOutput()
	if err != nil {
		t.Fatalf("drbdadm rejected the generated configuration for %q: %v: %s", vol.ID, err, out)
	}

	// dump re-renders the parsed configuration, so the authentication this
	// package wrote has to survive a round trip through drbdadm's own parser.
	dumped, err := exec.Command("drbdadm", "dump", vol.ID).CombinedOutput()
	if err != nil {
		t.Fatalf("drbdadm dump %q: %v: %s", vol.ID, err, dumped)
	}
	if !strings.Contains(string(dumped), "cram-hmac-alg") {
		t.Errorf("drbdadm's own dump has no cram-hmac-alg, so the peer is not authenticated:\n%s", dumped)
	}
}
