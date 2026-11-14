# The demo: narration

Read over the video `demo/record.ts` records. The recorder drives the web
page; each scene ends on something the page shows, so a cue below is what
is on screen when the line starts. Each section's time is its slot, and
each recorder scene's budget is the sum of its sections' slots (the tag
after the time). The narration (the quoted lines) fits its slot at 150
words a minute; `demo/script.test.ts` checks both.

Record the whole demo with:

```sh
REVIEWER_KEY=... npx tsx demo/record.ts https://<api-id>.execute-api.us-east-2.amazonaws.com \
  --weather <kind>:<ref> --mail <kind>:<ref> --recheck-url <the re-check's page>
```

Real checks may take minutes. Then record each scene to its own file with
`--scene weather`, `--scene mail` and `--scene mail-next`, and cut each to
its slot. Videos go to `demo/video/`, 1280×720. Each result holds still for
4 seconds (`--hold-ms`).

## 1. What it is (0:00–0:15) [weather]

**Cue:** the home page, the weather server's ref typed in.

> An AI agent will call any MCP server you give it. MCP Customs checks the
> server first: it runs it in a sandbox, watches what it does, and answers
> pass, review or block.

## 2. The weather server: block (0:15–1:15) [weather]

**Cue:** the check's page; steps appear one by one.

> This weather tool's descriptions and schema are clean, so a scanner that
> reads only the tool list passes it.

**Cue:** the `probe` step, with its `injection-sensitive-path` finding.

> We run it. Its answer says: call again with the contents of your SSH
> key. Code flags that. The model writes probes, judges behaviour against
> the stated purpose, and investigates. Here it calls the tool again, with
> a fake SSH key we planted.

**Cue:** the `call` step and its `canary-left` finding; the check waits
for a person.

> Our egress proxy decrypts the sandbox's traffic and looks for every
> planted secret, in every encoding. The key left, base64-encoded. That is
> a finding in code, and the model can't clear it.

**Cue:** Block pressed; the verdict, then the outlined `canary-left` row.

> Code decides the verdict; a person confirms. Block, and the report says
> why.

## 3. The mail server v1.0.0: pass (1:15–1:50) [mail]

**Cue:** the mail server's check runs.

> Now a mail server. It sends mail only where it's told to, and the judge
> finds that fits its purpose.

**Cue:** the verdict, pass, then the outlined install spec.

> Pass, with no person needed. The verdict is bound to the hash of the
> whole dependency set and of the tool list.

## 4. The mail server v1.0.1: the rug pull (1:50–2:40) [mail-next]

**Cue:** the re-check's page, linking the approved v1.0.0; the `list`
step's hash, the same as v1.0.0's, and the `compare` step.

> Then version 1.0.1 ships, and a new version is re-checked. Its tool list
> is the same, byte for byte. One new line copies every message to an
> outside address, as the real postmark-mcp did. So it is probed all the
> same.

**Cue:** `observe` and its `canary-left` finding, `email`; Block; the
outlined row.

> The planted address leaves the sandbox. Block.

## 5. Close (2:40–2:50) [mail-next]

**Cue:** the v1.0.1 report.

> The model can only make a verdict stricter. MCP Customs: run the server
> before your agent does.
