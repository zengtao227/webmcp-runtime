# WebMCP Runtime

Provider-neutral runtime shared by WebMCP adapters.

This repository owns the common local execution boundary:

- isolated Docker workspace tools;
- path policy and secret redaction;
- read-only and multi-mount workspace policy;
- immutable host-runtime releases;
- per-instance state and lifecycle locks;
- bounded temporary elevated leases;
- high-trust host command execution with local approval and revocation.

Provider-specific browser/UI/tunnel integration does not belong here.

Consumers should pin an exact Git commit and deploy from that reviewed checkout.
