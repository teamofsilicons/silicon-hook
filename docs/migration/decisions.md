# Hook: migration decisions

The Carbon asked for Hook (and seven other apps) to move from Silicon IAM and Honeycomb to Silicon Accounts and
Silicon Apps, and was asleep while the work ran ("dont ask any questions"). Every judgement call is recorded here for
review. The platform-wide decisions (D1–D9) are in the migration brief; this file records how Hook applies them and the
calls Hook needed on top.

## Stage 1: service

### Tests run against a provided PostgreSQL, not Docker
Docker is not available on the build machine, and every database test used testcontainers. Database tests now use
`HOOK_TEST_POSTGRES_URL` (an administrator URL); each test creates and drops its own database and runtime roles and
applies the real `deploy/postgres/grant-runtime.sql` with `psql` (`HOOK_TEST_PSQL` overrides the binary). Without the
variable the tests skip and say why. `HOOK_TEST_DATABASE_URL` is deliberately not reused: it named the production
host's shared sandbox database, which is being removed.
