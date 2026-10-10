# Public identifier cutover — 2026-09-23

Hook 0.9.0 is live at `1638bc6ab09fcb34d689bf51ecf9c4fcb43402d1`. Public readiness passes.

Both database migrations passed restored-copy rehearsals before live activation. Native API/worker and gateway are healthy, and the canonical frontend is promoted. Twenty-three browser sessions were converted, preserving production token bytes and ownership. Fresh c:saket login and explicit --org tos status succeeded. The initial status attempt omitted the required organization header; passing explicit context resolved it.

Frozen backup, mapping, migration, session conversion and activation receipts are retained in the protected operator directory `/tmp/consumer-cutover-20260923/`, including final-artifact-verification.json, fresh-cli-auth.json and service-specific SSM receipts. Public health was independently rechecked after all activations. Client/CLI crates are published. The six-platform GitHub v0.9.0 release is public after remote asset SHA256 verification. Honeycomb release `f8d9bdc0-c71d-4719-9ccd-6fe6ed8e940e` is accepted with archive SHA256 `1ccd10fc356851951c74c23de1a56c4e72f832fc50e83007e63cd364f7edffa2`. Hosted documentation was rebuilt, published and checked.
