# Kickoff prompt

Paste this into a new Claude Code session that runs on the owner's machine,
started in a clone of this repository (the desktop app or the CLI; a cloud
session can't reach the local Kind cluster). The theos clone next to it has
the `factory-ops` skill for driving the factory.

---

You run MCP Customs' build end to end. Read CLAUDE.md and docs/plan.md
first; they are the rules and the design. I've authorized you to run the
factory on this machine and to deploy. Don't ask me for anything except
what CLAUDE.md says only I can do, and ask for that once, when needed.

1. **Find the factory.** Check `kind get clusters` and the kubectl contexts.
   If a theos factory is running (namespace `theos-system`, release
   `theos`), use it; the theos clone's `factory-ops` skill says how to
   check its health. If none is, install the latest theos release on a new
   Kind cluster as theos's `docs/getting-started.md` says
   (`hack/quickstart.sh` does most of it). Don't touch other clusters.
2. **The Claude token.** Check that Secret `claude-credentials` in
   `theos-system` exists and is non-empty, by its length only; never print
   it. If it is missing, ask me to run `claude setup-token` and give me the
   one command that stores it, then go on with step 3 meanwhile.
3. **Add the project.** `helm upgrade` the release with `--reuse-values`,
   adding `mcp-customs` to `gitea.projects` and keeping every project
   already there. Wait until namespace `mcp-customs` has its GitProvider,
   catalog and Agents.
4. **Apply the Brief.** `kubectl apply -f brief.yaml`. Watch the Brief until
   it is Planned.
5. **Check the plan.** Compare the model, the Crews and the first issues
   with docs/plan.md and docs/c4.html: the three Containers (`checker`,
   `sandbox`, `web`), the DynamoDB DataStore, and issues that build the
   weather-tool demo end to end first (sandbox with its egress proxy, the
   code findings, the Checker's fixed checks and investigation loop, the
   web page). Correct what's wrong or missing with `spec.prompts`, never by
   editing the model by hand. Log each correction in the friction log.
6. **Watch the build.** Follow Tasks, pull requests and reviews in Gitea.
   When theos gets in the way, file an issue on JairJosafath/theos (labels
   `source/dev`, `status/proposed`, `kind/bug` or `kind/feature`) and add a
   friction-log row; work around it if it blocks, and say so in the issue.
   Commit the log here as it grows.
7. **Deploy.** When the checker, sandbox and web Containers have merged
   their first working versions, deploy each with `cdk deploy` to us-east-2
   with my AWS profile (ask me for the profile name if `aws sts
   get-caller-identity` fails). Run the weather-tool check end to end
   against the deployed stack.
8. **Then** the rug-pull demo and the "new and fine" path, by follow-up
   prompts in the order docs/plan.md ranks them.
9. **Submission.** Mirror the Container repositories to public GitHub
   repositories named `mcp-customs-<container>`. Record a demo run of the
   web page with Playwright's video recording, under 3 minutes, and write
   the script beside it. Write `docs/results.md` (what theos built alone,
   what needed a prompt, what needed a hand, time and tokens) and the
   Builder Center write-up with the architecture diagram. Tell me when
   the video is ready to upload and the write-up ready to paste; the
   deadline is Monday 2026-11-16, 13:00 PT.

Report to me in a few lines at each step's end, not before.
