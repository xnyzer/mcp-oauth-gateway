---
id: F-033
title: Watch the frozen OpenTelemetry exporters pulled in through ory/x
type: feature
status: BACKLOG
size:
created: 2026-10-12
done:
depends-on:
superseded-by:
---

# F-033 — Watch the frozen OpenTelemetry exporters pulled in through ory/x

## Intake

**Problem:** Two trace exporters are compiled into the binary that the gateway never uses and
cannot drop: `ory/fosite` imports `ory/x/otelx`, which imports the OpenTelemetry Zipkin and
Jaeger exporters. The Jaeger exporter was removed upstream long ago and is frozen at v1.17.0;
the Zipkin exporter is announced as "deprecated and will be removed in early 2027". A frozen
module receives no fixes, and the first OpenTelemetry release it no longer compiles against
turns a routine bump into a blocked one — found during F-031a, when `go get` printed the
deprecation notice.

**Idea:** Nothing to build now — the gateway configures no tracing, so the code is never
executed, and both exporters still compile against OpenTelemetry 1.47. Re-check on a date, and
earlier on a trigger, so the removal is met on our schedule rather than in the middle of a
security bump.

**Re-check on 2027-01-15**, or earlier as soon as one of these happens:
- an OpenTelemetry bump fails to build;
- `govulncheck` or a Dependabot alert names either exporter;
- `ory/fosite` or `ory/x` publishes a new version.

**Solution sketch:**
- At the re-check: has OpenTelemetry removed the Zipkin exporter, and at which last version;
  has `ory/x` dropped the two imports (it had not on 2026-10-12, at v0.0.729, and carried no
  issue about it); does the current tree still build against the then-current OpenTelemetry.
- If `ory/x` has not moved: raise it upstream, and decide whether holding OpenTelemetry at the
  last compatible version is acceptable for an auth boundary, or for how long.
- No new dependency; a replacement for Fosite is out of scope here.

**Dependencies:** none.
