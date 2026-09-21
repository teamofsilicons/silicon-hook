# Canonical IAM compatibility deployment, 2026-09-21

Source: `f9745c3261021b15d7085b6b43d21cc8ec53f293`.

The backend accepts canonical IAM identity strings through IAM client 3.0.0.
Existing Hook resource identifiers and the public CLI 0.7.1 contract are retained.

The ARM64 native archive SHA-256 is
`4806bf6d7940168ad6fdace2341b94f82af0039be10ae6d7455f8b6988500e17`.
SSM deployment `5ea0f9a8-525b-4124-8642-a1495a4d428b` installed it on
`i-04398b332e0a3c1b7` at `/opt/silicon-hook/releases/f9745c326102`.
The previous release was retained at
`/opt/silicon-hook/backups/before-native-20260921T084223Z` and backed up to the
existing private standalone artifacts bucket.

Validation: 133 library tests, nine focused IAM tests, strict workspace Clippy,
successful ARM64 native build, both API and worker active, and readiness 200.
The existing public version endpoint reports the package version and an unknown
commit; the immutable archive and systemd release paths identify this deployment.

This records compatibility readiness before IAM's canonical database switch.
Retained authentication and online delivery checks follow the central cutover.
