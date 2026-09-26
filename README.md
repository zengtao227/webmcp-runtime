# WebMCP Runtime

Provider-neutral runtime shared by WebMCP adapters.

This repository owns the common local execution boundary:

- isolated Docker workspace tools;
- path policy and secret redaction;
- read-only and multi-mount workspace policy;
- immutable host-runtime releases;
- per-instance state and lifecycle locks;
- two access levels: mounted folders with per-folder Write, and time-bounded Host Access (high-trust host command execution with local approval and revocation; the container never changes).

Provider-specific browser/UI/tunnel integration does not belong here.

Consumers install it as a pinned release artifact: each GitHub Release carries one archive whose artifact id binds the Git commit to the payload digest; adapters pin the artifact id and the archive sha256 and verify both before use.
