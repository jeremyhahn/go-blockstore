# Managed by go-blockstore (provider "drbd"). Do not edit by hand.
# Volume: vol1
# Generated: 2026-08-27T12:00:00Z
resource "vol1" {
    device    minor 3;
    disk      "/dev/vg0/vol1";
    meta-disk internal;

    net {
        protocol C;
        verify-alg crc32c;
        csums-alg  crc32c;
        # NO PEER AUTHENTICATION. Provisioned with allow_unauthenticated_peers
        # set: any host that can reach this address and speak DRBD can present
        # itself as the peer.
    }

    on "node-a" {
        node-id 0;
        address ipv4 192.0.2.1:7792;
    }

    on "node-b" {
        node-id 1;
        address ipv4 192.0.2.2:7792;
    }
}
