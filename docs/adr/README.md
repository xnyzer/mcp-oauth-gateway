# Architecture Decision Records

Optional, lightweight (MADR-style). One file per durable architecture decision:
`NNNN-short-title.md`, numbered ascending — copy `0000-template.md` to start.

Rule of thumb: a decision about one feature lives in the Decisions section of its file
under `features/`; an ADR is for choices that shape the system long-term (storage engine,
protocol, framework) and deserve their own page — the feature file links it. Never
rewrite an accepted ADR — supersede it with a new one.
