### Added

- **A liveness-oracle seam, so a deployment can answer the question the provider
  cannot.** `common.LivenessOracle` asks whether an attachment still has a live
  owner; `pkg/local` takes one through `Options.LivenessOracle`. Whether an
  attachment has an owner at all is a property of how a system is DEPLOYED — a
  leased HA controller has one, a CSI node plugin has the pod, a host running
  one component over local disks has none — so the provider exposes the question
  and the deployment supplies the answer, rather than a library every deployment
  consumes baking in one deployment's assumption. go-blockstore takes no
  dependency on `pkg/ha`, on a CSI layer, or on anything upstream (#41).

  The reaper consults it at **exactly one** point: a mapping this node made on
  the boot that is still running. That is the only case the boot ID cannot
  settle, and it is the case that motivates the whole guard — an init container
  attaches, mounts, exits, and the host stays up, leaving a mapping every local
  fact calls live. It is deliberately NOT consulted on an ended boot, which is
  already proof and where an oracle outage could only erase a verdict reached
  without one, nor on another node's mapping.

- **`liveness unknown`, a verdict for an oracle that could not answer.** Not
  `live`, which would make an oracle outage look like a fleet with no orphans,
  and not `orphaned`, which would point anything acting on these verdicts at
  volumes live workloads are using. `Liveness` is a two-valued enumeration
  rather than a `bool` so that the reclaimable answer cannot arrive as an
  implementation's zero value: `common.LivenessOf` refuses the zero value, an
  unrecognized value, a nil oracle, and any value returned beside an error, all
  as `ErrLivenessIndeterminate`.

- **`Posture()` reports the oracle, present or absent.** `attachment liveness:
  NOT CHECKED` names the consequence rather than the setting — a mapping made on
  this boot is reported as live whether or not anything still holds it — because
  an absent oracle is legitimate and otherwise indistinguishable from a
  deployment that needs none.

### Unchanged

- **Nothing tears a mapping down.** `InspectMappings` still reports and removes
  nothing; the acting half deleted in #43 stays deleted. This lands the fact that
  would make removal decidable, not the removal.
