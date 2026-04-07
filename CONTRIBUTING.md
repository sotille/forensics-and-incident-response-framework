# Contributing to the Forensics and Incident Response Framework

Thank you for your interest in contributing. This framework is part of the Techstream DevSecOps ecosystem and follows the same contribution standards as the other Techstream repositories.

## What Contributions Are Welcome

- **New investigation playbooks**: Documented compromise types with evidence collection steps, investigation procedures, and remediation guidance
- **Updated tooling commands**: As forensics tooling evolves (cosign, syft, grype, kubectl, AWS CLI), command syntax and output formats change — corrections welcome
- **New evidence sources**: Additional cloud providers, CI platforms, container runtimes, or secret managers not currently covered
- **Agent forensics content**: This is an evolving area; contributions documenting real-world agent forensics scenarios are particularly valuable
- **Corrections**: Factual errors, broken commands, outdated procedures

## What to Avoid

- Marketing language or vague recommendations without concrete procedures
- Content that duplicates what is already covered in the referenced upstream playbooks without adding new technical depth
- Untested commands or procedures that have not been verified against a real environment

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/add-gcp-forensics`
3. Make your changes, following the writing style guidelines below
4. Open a pull request with a clear description of what was added or changed and why

## Writing Style

This framework uses the same style conventions as other Techstream repositories:

- **Technical depth over breadth**: Prefer one well-documented procedure over five shallow ones
- **Concrete commands**: Every investigation procedure must include real, executable commands. Use `<PLACEHOLDER>` notation for values that vary by environment
- **Tables for structured comparisons**: Evidence types, severity levels, tool comparisons
- **Cross-references**: Link to related documents in this framework and in other Techstream repositories
- **No filler text**: Every paragraph must add information not present elsewhere in the document

## Playbook Numbering Convention

| Domain | Prefix | Current Range |
|--------|--------|---------------|
| Pipeline Forensics | PL- | PL-01 to PL-08 |
| Cloud/Container Forensics | CF- | (unassigned; use next available) |
| Supply Chain Forensics | SC- | (unassigned) |
| Agent Forensics | AF- | AF-01 to AF-04 |
| Identity/Credential Forensics | IC- | (unassigned) |
| Runtime Forensics | RF- | (unassigned) |

When adding a new playbook, use the next available number in the appropriate domain prefix sequence.

## License

By contributing to this project, you agree that your contributions will be licensed under the Apache License, Version 2.0, consistent with the existing license of this repository.
