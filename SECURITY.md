# Security policy

## Authorized use

Indago is a testing tool. Use it only on systems you own or have explicit
written permission to test. The operator is responsible for the scope entered
into a project and for every request the tool sends. The project maintainers do
not authorize testing of third-party systems.

## Reporting a vulnerability in Indago

Please do not open a public issue for a security bug in Indago itself.

Use GitHub's private vulnerability reporting on
<https://github.com/xcupi/indago/security/advisories/new>, or contact the
maintainer through the GitHub profile linked from the repository. Include:

- the affected version or commit;
- a minimal reproduction;
- the impact you believe it has;
- any suggested fix, if you have one.

Do not include real credentials, customer data, or third-party target data in a
report. Redact secrets and use synthetic examples.

## Scope of this policy

This policy covers the Indago codebase and its local server. It does not cover
targets you scan with Indago, bug-bounty platform policies, or third-party
provider APIs (Anthropic, OpenAI, YesWeHack, and others).

## Credential handling

Runtime credentials live under the data directory, not in the repository:
provider keys in `data/llm/`, OAuth credentials in `data/claude/` and
`data/chatgpt/`, and saved browser sessions in `data/auth/`. The UI never
echoes a stored key back. If you believe a credential was committed, rotate it
first, then report the exposure privately.
