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
| [docs/c4.html](docs/c4.html) | The C4 views: context, containers, and where code decides and the model judges ([published](https://claude.ai/artifact/NLmoPPJJBK9V3KgXNLpLDq)) |

The code is not here. theos makes one repository per Container (`checker`,
`sandbox`, `web`) in its own Git host; they are mirrored to GitHub for the
submission.
