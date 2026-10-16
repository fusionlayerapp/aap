# AAP — Governance

This document describes how the Agent Action Protocol (AAP) is maintained, how changes are proposed and accepted, and how intellectual property is licensed.

## 1. Stewardship

AAP is stewarded by the FusionLayer core team (GitHub: [fusionlayerapp](https://github.com/fusionlayerapp)) as a sibling open specification to the Unified AI Context Protocol ([UACP](https://github.com/fusionlayerapp/uacp)).

When at least three independent implementations pass conformance validation (`tools/aap-validate`), stewardship will transition to a multi-organization working group.

## 2. Change Process

- **Editorial** — Clarifications, examples, non-normative text. Patch version bump.
- **Additive** — Backward-compatible optional fields, capability descriptors, or vendor mapping extensions. Minor version bump.
- **Breaking** — Removal or incompatible modification of required fields or validation rules. Requires a 14-day public comment window and a major version bump.

## 3. Intellectual Property & Licensing

- All repository contents (schemas, tools, test vectors, and specification documents) are licensed under the **Apache License, Version 2.0** (see [`LICENSE`](LICENSE)), which includes an express copyright and patent license (§2–§3).
- At the recipient's option, specification prose (`spec/`, `README.md`, `GOVERNANCE.md`) may also be used under **CC BY 4.0**.
- Contributors certify that they have the right to submit contributions under these terms ([Developer Certificate of Origin](https://developercertificate.org)).

## 4. Security

Security vulnerabilities in the AAP specification, JSON schemas, or `aap-validate` tooling should be reported privately per [`SECURITY.md`](SECURITY.md).
