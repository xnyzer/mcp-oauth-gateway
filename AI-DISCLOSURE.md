# AI Disclosure

This project is developed using **Claude Code** (by Anthropic) as the primary development tool. In the interest of transparency, this document describes how AI is involved in the development process.

## Roles

**Human (Project Owner):** Defines requirements, makes architectural and security decisions, manages the project, tests functionality, and ensures the end result meets expectations. Does not write or review code at a technical level.

**AI (Claude Code):** Writes all code, proposes technical solutions, implements features, and maintains documentation. Operates under the direction and approval of the project owner.

## How AI is used

- **All code** in this project is written by Claude Code
- **Architecture and technical decisions** are proposed by the AI and confirmed or adjusted by the project owner
- **Planning and documentation** are created collaboratively
- **Testing** is performed by the AI (automated tests) and the project owner (functional/user perspective)

## Transparency

- Every commit includes a `Co-Authored-By: Claude` tag
- The project owner steers direction, priorities, and acceptance criteria
- The AI does not deploy, publish, or make irreversible changes without explicit approval

## Why this matters for a security tool

mcp-oauth-gateway is a public authentication boundary. AI-written code does not exempt it from scrutiny: it is built on a vetted OAuth library (no hand-rolled crypto), the design is fail-closed, and a mandatory human-reviewed security review precedes any public exposure. The quality of the result depends on both sides: precise requirements and competent execution, plus deliberate review of the security-critical paths.
