# Security policy

JinnexGuard reads repositories and packages that may be malicious, so a flaw in
it matters: target code that ends up being executed, a file written outside the
temporary folder while extracting a package, or a report that lets instructions
through to the agent reading it.

## Reporting a vulnerability

Use **Security → Report a vulnerability** in this repository (a private GitHub
advisory). Please do not open a public issue. Include the target or a minimal
example that reproduces it, and the version (`jinnexguard --version` or the
commit).

## What is not a vulnerability

A malicious repository that JinnexGuard **does not flag** is a false negative,
not a vulnerability: the tool gives signals, not guarantees. Please report
those as a regular issue, ideally with the pattern that slipped through.
