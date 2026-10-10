# Hook history

These records describe Hook before 1.0, when it signed in with the previous
identity service, ran shared test environments and shipped through the previous
app distribution. They are kept as written, as evidence of what was released,
deployed and verified at the time. None of them is a current instruction: for
how Hook works now, start at the [documentation index](../README.md).

They are not published on the docs site or bundled with the CLI. Links between
them still work; links to guides that have since changed point at the last
pre-1.0 version of the repository (commit `d621aba`).

| record | what it covers |
| --- | --- |
| [releases-before-1.0.md](releases-before-1.0.md) | how 0.x releases were built and the 0.7.0, 0.7.1 and 0.8.0 notes |
| [release-iam5.md](release-iam5.md) | the coordinated 0.10 sign-in release |
| [build-status.md](build-status.md), [implementation-progress-2026-09-13.md](implementation-progress-2026-09-13.md) | implementation and rollout status in September 2026 |
| [iam/README.md](iam/README.md) | the previous sign-in boundary |
| [testing/](testing/README.md) | the shared test environments and their lifecycle contract |
| [ting-implementation.md](ting-implementation.md), [ting-integration-issues.md](ting-integration-issues.md) | how 0.8 delivery through Ting was built and the constraints found |
| [frontend-iam5-contexts.md](frontend-iam5-contexts.md) | the earlier browser gateway's account contexts |
| [public-identifier-migration.md](public-identifier-migration.md) | the September 2026 public identifier cutover (migration 0017) |
| [verification/](verification/README.md) | release and deployment evidence for 0.5 to 0.8 |
| [deploy/](deploy/canonical-iam-2026-09-21.md) | host records of the September 2026 cutovers |

The move to Silicon Accounts and Silicon Apps is recorded in
[docs/migration](../migration/progress.md).
