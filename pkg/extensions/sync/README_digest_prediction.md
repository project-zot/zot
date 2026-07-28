# OCI digest prediction for on-demand sync skip checks

This note describes how zot predicts the digest an image will have **after** regclient
`mod.WithManifestToOCI` + `mod.WithManifestToOCIReferrers`, without running a full sync.
It compares **remote registry call counts** for:

1. **Pre-`predictOCIDigest`** — hand-rolled `convertDockerManifestToOCI` / `convertDockerListToOCI` in `remote.go` (removed when `predictOCIDigest` landed)
2. **`predictOCIDigest`** — in-memory mirror of regclient manifest conversion (`oci_digest_predict.go`)
3. **`mod.Apply`** — what regclient runs during an actual sync conversion

References:

- regclient: [`github.com/regclient/regclient`](https://github.com/regclient/regclient) v0.11.5 (`go.mod`)
- Conversion mods: `mod.WithManifestToOCI`, `mod.WithManifestToOCIReferrers` ([`mod/manifest.go`](https://github.com/regclient/regclient/blob/v0.11.5/mod/manifest.go))

---

## Why prediction exists

On-demand sync uses `CanSkipImage` to avoid re-copying an image that is already stored with the
digest regclient would produce after OCI conversion. That requires comparing:

- **Local stored digest** — from `mod.Apply` at commit time (OCI layout in the sync session)
- **Remote “would-be” digest** — must match post-conversion OCI, not the upstream Docker digest

For Docker images (e.g. `registry.k8s.io/pause:3.10.1`), the upstream manifest-list digest and the
post-`mod.Apply` OCI index digest differ. Comparing raw remote vs local caused endless resync loops.

`predictOCIDigest` mirrors regclient’s in-memory manifest conversion so skip checks can compare
OCI-to-OCI without running `ImageCopy` + `mod.Apply` on every tag lookup.

---

## What each approach does

| Approach | When used | Fetches blobs? | Mirrors `WithManifestToOCIReferrers`? |
|----------|-----------|----------------|----------------------------------------|
| **Pre-`predictOCIDigest`** | `GetOCIDigest` before this change | Yes — `BlobGetOCIConfig` per Docker platform manifest | No |
| **`predictOCIDigest`** | `GetOCIDigest` today | No — manifest JSON only; every index child is fetched recursively | Yes |
| **`mod.Apply`** | Actual sync after `ImageCopy` | Yes — full DAG (configs, layers, referrers) | Yes |

`WithManifestToOCI` does **not** rewrite config or layer **blob** bytes. It rewrites **descriptor
media types inside manifest JSON** (config + layers). That can change a manifest digest even when
the manifest envelope already uses OCI media types.

---

## Remote calls for one `GetOCIDigest(repo, tag)` lookup

Let **P** = number of platform manifests in a multi-arch index. Let **N** = total manifest nodes
in the tree (root + every child index entry, recursively).

| Image shape | Pre-`predictOCIDigest` | `predictOCIDigest` | `mod.Apply` (`dagGet` only, remote) |
|-------------|------------------------|--------------------|-------------------------------------|
| OCI single manifest | 1 `ManifestGet` | 1 `ManifestGet` | 1 `ManifestGet` + 1 `BlobGetOCIConfig` + 1 `ReferrerList` |
| OCI multi-arch index (P platforms) | **1 `ManifestGet`** (root only) | **1 + P** `ManifestGet` | **1 + P** × (`ManifestGet` + `BlobGetOCIConfig` + `ReferrerList`) + referrer recursion |
| Docker single manifest | 1 `ManifestGet` + 1 `BlobGetOCIConfig` | 1 `ManifestGet` | Same as OCI single row |
| Docker manifest list (P) | **1 + 2P** (`ManifestGet` + `BlobGetOCIConfig` per child) | **1 + P** `ManifestGet` | **1 + P** × (`ManifestGet` + `BlobGetOCIConfig` + `ReferrerList`) + … |
| Hybrid: OCI index + Docker children | **1 `ManifestGet`** (root treated as OCI — wrong digest) | **1 + P** `ManifestGet` | Full tree walk (as multi-arch) |
| Hybrid: Docker list + OCI children | **1 + 2P** (if root is docker list) | **1 + P** `ManifestGet` | Full tree walk |
| Nested indexes (depth D, N total entries) | Often **1** (root only) | **N** `ManifestGet` | **N** × (`ManifestGet` + `BlobGetOCIConfig` + `ReferrerList`) + … |

In general, `predictOCIDigest` performs **one `ManifestGet` per manifest node** in the tree — the
same manifest walk as `mod.Apply`’s `dagGet`, but without config blobs, layer blobs, or referrer
list calls.

### Call types

- **`ManifestGet`** — fetch manifest JSON (index or platform manifest)
- **`BlobGetOCIConfig`** — fetch image config blob (pre-`predictOCIDigest` + `mod.Apply` `dagGet`; not used by predictor)
- **`ReferrerList`** — `mod.Apply` `dagGet` only; predictor does not call this
- **`ManifestPut`** — `mod.Apply` `dagPut` when manifests change (local ocidir after `ImageCopy`; not used for prediction)

---

## `predictOCIDigest` vs pre-`predictOCIDigest` (summary)

| Scenario | Call count | Correctness |
|----------|------------|-------------|
| Docker multi-arch | **~half** pre-`predictOCIDigest` (`1+P` vs `1+2P`) | `predictOCIDigest` matches `mod.Apply`; pre-`predictOCIDigest` matched simple docker lists but not referrers |
| Docker single | **Fewer** (`1` vs `2`) | `predictOCIDigest` matches `mod.Apply` (manifest media-type change only; config blob not needed for digest) |
| Pure OCI multi-arch | **More** (`1+P` vs `1`) but still cheap (manifest JSON only) | Both correct for skip (no conversion); extra child fetches are required for correctness (see below) |
| Hybrid indexes | Pre-`predictOCIDigest` often **wrong** (1 call, no child conversion) | `predictOCIDigest` walks all children and matches regclient |

---

## vs `mod.Apply` on the real sync path

Skip checks **do not** call `mod.Apply`. During sync, conversion runs only when
`isConverted && !skipped && !PreserveDigest` in `syncImage`:

```go
mod.Apply(ctx, service.rc, localImageRef,
    mod.WithRefTgt(localImageRef),
    mod.WithManifestToOCI(),
    mod.WithManifestToOCIReferrers(),
)
```

| Phase | Where | Cost |
|-------|-------|------|
| **`ImageCopy`** (`syncRef`) | Remote → local ocidir session | All manifests + all blobs (dominant) |
| **`mod.Apply`** | Local ocidir | `dagGet` (manifest + config + referrers tree) + `ManifestPut` for changed manifests |
| **`predictOCIDigest`** | Remote registry | **N** `ManifestGet` calls (full manifest tree); no blobs or referrer lists |

Using `mod.Apply` **for prediction on the remote** (without a prior copy) would require `dagGet`
on the upstream registry: config blobs, referrer lists, and recursive referrer walks — far heavier
than `predictOCIDigest`, and would still need `ManifestPut` to materialize converted manifests.

Tests in `oci_digest_predict_internal_test.go` use `ImageCopy` + `mod.Apply` on a **local** ocidir
as the oracle; that matches the conversion step in `syncImage`, not the remote prediction path.

---

## Worked examples

### Docker manifest list with P ≈ 20

(e.g. `registry.k8s.io/pause:3.10.1`)

| Method | Approx. remote calls |
|--------|----------------------|
| Pre-`predictOCIDigest` (`convertDocker*`) | **41** (1 + 20×2) |
| `predictOCIDigest` | **21** (1 + 20) |
| `mod.Apply` `dagGet` (hypothetical remote) | **61+** (1 + 20×3, plus referrers) |
| Full sync | `ImageCopy` of entire image + local `mod.Apply` |

### Pure OCI multi-arch index with P ≈ 20

| Method | Approx. remote calls |
|--------|----------------------|
| Pre-`predictOCIDigest` | **1** (root only; sufficient when no conversion) |
| `predictOCIDigest` | **21** (1 + 20; all children fetched) |
| `mod.Apply` `dagGet` (hypothetical remote) | **61+** |

Extra child `ManifestGet` calls on pure OCI images are the trade-off for matching regclient when
any child might need interior descriptor conversion.

---

## `isConverted` and when sync runs `mod.Apply`

`predictOCIDigest` returns `(predictedDigest, originalDigest, isConverted, err)`.

`isConverted` is true when regclient would change **any** manifest in the tree (not only when the
root is Docker), e.g.:

- Docker manifest list → OCI index
- Docker platform manifest under an OCI index
- OCI manifest envelope with docker config/layer descriptor media types inside
- Index entries with docker referrer annotations (`WithManifestToOCIReferrers`)

Sync gates `mod.Apply` on this flag so pure OCI images skip conversion.

---

## Why every index child is fetched

`fetchManifestNode` calls `ManifestGet` on **every** child listed in an index (and recurses into
nested indexes). Index child descriptors alone are not enough to predict conversion:

| What you see in the index | What `WithManifestToOCI` may still change |
|---------------------------|-------------------------------------------|
| Child `mediaType` is OCI manifest | `config.mediaType` and `layers[].mediaType` inside the manifest JSON |
| Child `mediaType` is Docker manifest | Top-level manifest `mediaType` plus interior descriptors |
| Nested index | Recurse |

Example: an OCI index whose children use `application/vnd.oci.image.manifest.v1+json` but whose
manifest bodies still list docker config/layer media types. Regclient rewrites those interior
descriptor strings, producing a new manifest digest and a new parent index digest. Without fetching
the child manifest body, the predictor cannot know whether that rewrite is needed.

This does **not** mean config or layer **blobs** are fetched — only manifest JSON.

---

## Tests

`TestPredictOCIDigestMatchesRegclient` builds fixtures via `pkg/test/image-utils` + `write.go`
(zot local store → ocidir layout) and asserts:

```text
predictOCIDigest(...) digest == mod.Apply(WithManifestToOCI, WithManifestToOCIReferrers) digest
```

Cases include OCI single/multi-arch, OCI artifacts with OCI/docker subjects, docker artifacts
with OCI/docker subjects, docker lists, docker-from-OCI conversion, hybrid indexes
(OCI index + docker children, docker list + OCI children, OCI index + OCI children with docker
interior descriptors), and three-level nested indexes:

| Root | Mid | Leaf platforms |
|------|-----|----------------|
| OCI | OCI | OCI |
| OCI | OCI | Docker |
| OCI | Docker | OCI |
| Docker | OCI | OCI |
| OCI | Docker | Docker |

---

## Possible follow-ups

1. **`PreserveDigest: true`** — skip prediction conversion alignment; compare raw digests instead
   (see `examples/config-docker-compat-sync.json` workaround for docker2s2).
