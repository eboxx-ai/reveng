# Inspect APK signature schemes (v1–v3.1)

## Outcome and scope

Answer, statically, **who signed a selected local APK, under which schemes, and
whether the signature covers the current bytes**. This closes a gap REA's own
Android inventory documents: "ZIP inventory cannot see the APK Signing Block, so
an empty signing array does not mean the APK is unsigned"
(`src/domain/android/androidApplication.ts`).

Static format inspection within existing offline-artifact authority: no Android
code executes, no device or `adb`, no acquisition, no mutation.

## Inspection contract

- v1 (JAR) signing detected from `META-INF` names in the central directory.
- The APK Signing Block located from the ZIP end-of-central-directory (Zip64
  followed) and framed into id-value pairs; v2, v3 and v3.1 signers decoded:
  digests by signature-algorithm id, X.509 certificate DER, v3 min/max SDK,
  additional attributes.
- Certificate identity as SHA-256 over the raw embedded DER (as apksig
  hashes it); subject, issuer, serial, ISO 8601 validity and key algorithm via
  the platform X.509 parser, each `null` when unreadable rather than guessed.
- The v3/v3.1 proof-of-rotation lineage (version 1) decoded into nodes:
  certificate and the capability flags retained by that node's certificate.
  Node signatures are not verified: the lineage is what the APK declares. A
  lineage that cannot be decoded is reported with `decode_error`.
- Source-stamp block presence.
- Self-consistency: the v2/v3 content digest is recomputed for SHA-256/SHA-512
  and compared with each signed digest (`matches_apk`), rolled up into
  `posture.self_consistent`. Verity digests are not recomputed (`null`).
- A derived tamper-surface posture that keeps observation and declaration
  apart: `schemes_agree_on_signer` compares each block scheme's signer
  certificate _set_; `signer_change_declared_by_rotation` says whether a
  declared lineage covers a difference. Also `v1_only`, strongest scheme,
  rotation and source-stamp presence.
- Unknown is never reported as absent: a central directory that cannot be
  walked, or whose record count does not consume its declared extent, is an
  input error (v1 presence would otherwise be guessed); a signer without a
  certificate makes agreement `null`; scheme errors name the scheme and reason.

## Authority

Identity and self-consistency, never trust: no cryptographic signature
verification, no certificate-chain or revocation evaluation, no authenticity
claim. A full verifier would be a separate scope decision.

## Resource admission

One bounded read of the archive (512 MiB cap, no-follow, change-detected).
Every ZIP-tail and signing-block size/offset is checked against the buffer.
Signers per scheme and lineage nodes are capped at 32 (format-justified: one
node per rotation, one v3 signer per SDK range); pairs and per-signer elements
at 4096. The result size is projected from decoded counts before
materialisation (an estimate), and the exact serialized size is checked against
the 8 MiB output budget (authoritative); over-budget is a capacity refusal, not
truncation. The content digest is
computed at most once per algorithm in 1 MiB chunks. Peak memory is about
twice the file size (the shared stable read concatenates its chunks) plus
bounded decoding overhead; the digest passes run synchronously (a streamed positioned-read design is
a follow-up).

## Verification

`npm run verify:apk-signature` (Android SDK `apksigner` + `aapt2`, JDK
`keytool`): builds a real minimal APK, signs default v2+v3, v1-only, a rotated
lineage, rotation carried by v3.1, a source stamp and a tampered copy, and cross-checks REA against `apksigner verify` and
`apksigner lineage` through CLI and MCP in Evidence parity, with the advertised
schema validated. SDK-free unit and adapter tests cover framing (including Zip64
and damaged archives), signer and lineage decoding with caps, the digest
algorithm (including a pooled-Buffer regression), set-based posture, the output
budget, and the provider's error surfaces. Independent review before handoff.

Format reference: APK Signature Scheme v2/v3 —
https://source.android.com/docs/security/features/apksigning
