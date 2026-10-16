# APK signature schemes

REA reads the signing of a selected local Android APK (or ZIP/AAB) statically,
so an analyst can answer **who signed this, under which schemes, and whether the
signature still covers these bytes** before trusting or triaging it. The reader
is in-process and needs no external engine: it parses the ZIP tail and the APK
Signing Block, reads certificates with the platform X.509 parser, and
recomputes the content digest. No Android code executes, and no device or
`adb` is involved.

CLI and MCP share one workflow and return artifact-bound Evidence inline.

```sh
rea inspect-apk-signature /path/app.apk
```

## What it reports

- **Schemes present:** v1 (JAR signing in `META-INF`, from the central
  directory), and the APK Signing Block's v2, v3 and v3.1.
- **Per signer:** the certificate's **SHA-256 fingerprint over the raw embedded
  DER** (the same value `apksigner --print-certs` prints), plus subject, issuer,
  serial, ISO 8601 validity and public-key algorithm when the X.509 parser can
  read them (each is `null` otherwise); declared digest algorithms; and for
  v3/v3.1 the bound min/max SDK.
- **Key rotation (v3/v3.1):** the declared proof-of-rotation lineage, oldest
  first. Each node carries its certificate and the capability flags **retained
  by that node's own certificate** after rotation (installed data, shared UID,
  permission, rollback, auth). A lineage attribute that cannot be decoded is
  reported with `decode_error`, never silently emptied.
- **Source stamp:** whether a Play source-stamp block is present.
- **Self-consistency:** for SHA-256/SHA-512 digests, REA recomputes the
  v2/v3 content digest and reports `matches_apk` per digest and
  `posture.self_consistent`. A single flipped byte in any entry makes it
  `false`.
- **Tamper-surface posture** (derived from the facts above):
  - `v1_only`: only JAR signing, so the signature is strippable.
  - `schemes_agree_on_signer` (observed): every present block scheme presents
    the same _set_ of signer certificates. An extra signer in one scheme is
    disagreement; a signer without a certificate makes it `null` (unknown).
    Build-tools 33+ rotate through v3.1 by default, so a rotated app usually
    reads `false` here and `true` below.
  - `signer_change_declared_by_rotation` (declared): the signers differ, but
    each appears in a lineage the APK declares. Read the two together: a
    legitimately rotated APK shows `false` / `true`; signers that differ with
    no covering lineage show `false` / `false`.
  - `strongest_scheme`, `rotation_present`, `source_stamp_present`,
    `self_consistent`.

## What it does not claim

This is **identity and self-consistency, not trust**. Signatures are not
cryptographically verified, certificate chains and revocation are not
evaluated, and nothing here says an app is authentic. `self_consistent: true`
means the signed digest matches the current bytes; it does not prove who made
them. Rotation-lineage node signatures are not verified either, so a lineage is
what the APK _declares_: an attacker who re-signs an APK can declare any
lineage, which is why `signer_change_declared_by_rotation` is kept apart from
the observed agreement. SHA-256 identifies exact bytes, not authenticity.

Not yet read: v4 `.apk.idsig` (a sibling file), the PKCS#7 certificate inside a
v1 signature block, verity (`0x0421`/`0x0423`/`0x0425`) digests (reported with
`matches_apk: null`), the `X-Android-APK-Signed` stripping marker, and the
source-stamp certificate.

## Bounds and errors

The archive is read once, bounded at 512 MiB, without following symlinks and
with change detection. Every size and offset in the ZIP tail and signing block
is checked against the buffer before use. Signers per scheme and lineage nodes
are capped at 32 each (real APKs use a handful). The report's size is
estimated from those counts before anything is materialised, and the exact
serialized size is then checked against an 8 MiB output budget (the exact check
is authoritative); an over-budget report is refused, not truncated. Peak memory
is about twice the file size plus bounded decoding overhead.

A file that is not a ZIP is refused as an unsupported target. A damaged ZIP
(local headers but no end-of-central-directory), a central directory that
cannot be walked or whose declared record count does not account for all of
its bytes, or a malformed signing block or signer is an input error naming the
scheme and reason. When the central directory is not immediately followed by
the end-of-central-directory record (a declared-size mismatch or a Zip64
record), the content digest is not recomputed and a limitation says so. A
rotation attribute that cannot be decoded still counts as `rotation_present`
(the attribute exists) and carries its `decode_error`.

Verified by the `verify:apk-signature` real lane. It builds a real minimal APK
with `aapt2`, signs it with the SDK's `apksigner` (default v2+v3, v1-only, a
rotated key lineage, rotation carried by v3.1, a source stamp, and a tampered
copy), and cross-checks REA against
`apksigner verify --print-certs` and `apksigner lineage --print-certs` through
the CLI and MCP.
