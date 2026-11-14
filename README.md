# MCP Customs

Scanners read what an MCP server says. MCP Customs runs it and watches what
it does, before an AI agent is allowed to use it: a pass, review or block,
with a report that says why.

An entry for the AWS Builder Center weekend challenge "No Pipeline, No
Problem" (deadline Monday 2026-11-16, 13:00 PT), built by
[theos](https://github.com/JairJosafath/theos) from a Brief.

| File | What it is |
| --- | --- |
| [brief.yaml](brief.yaml) | The whole input theos gets: the product in plain words |
| [docs/plan.md](docs/plan.md) | The product, the security review, the steps, and the friction log of what theos got wrong |
| [docs/kickoff.md](docs/kickoff.md) | The prompt that starts the build: an orchestrator cloud session and the Crew sessions it starts |
| [docs/c4.html](docs/c4.html) | The C4 views: context, containers, and where code decides and the model judges ([published](https://claude.ai/artifact/NLmoPPJJBK9V3KgXNLpLDq)) |

The code is not here. As theos wants, each Container has a repository of
its own: `mcp-customs-checker`, `mcp-customs-sandbox` and `mcp-customs-web`,
scaffolded with theos's templates and built by Claude Code cloud sessions
from issues.
