# Contracts between the parts

The parts of docs/c4.html are packages in one Go module (`src/`), built by
different sessions at once. This file is what they agree on. Change it in
the same pull request as the code that needs the change, and say so in the
pull request.

## Layout

| Path                                | What                                                                                                               |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `src/cmd/checker`                   | The Checker: the durable function's `main`                                                                         |
| `src/cmd/web`                       | The web and API function's `main`                                                                                  |
| `src/cmd/harness`                   | The sandbox harness's `main`, run in the MicroVM image                                                             |
| `src/internal/findings`             | Code-only findings: hidden characters, injection patterns, canary matching. No model, no network                   |
| `src/internal/canary`               | Fresh canaries per run, in real formats with valid checksums                                                       |
| `src/internal/verdict`              | The verdict rules: code findings the model can't clear; the model only stricter; error gives review                |
| `src/internal/harness`              | The harness: MCP client, package install, egress proxy, observations                                               |
| `src/internal/checker`              | The fixed checks, the action registry and interpreter, the judge and its investigation loop                        |
| `src/internal/store`                | DynamoDB and S3 access shared by the Checker and the web function                                                  |
| `src/internal/web`                  | Handlers and `html/template` pages                                                                                 |
| `src/demo/weather`, `src/demo/mail` | The demo MCP servers, each its own `main`                                                                          |
| `sandbox/Dockerfile`                | The MicroVM image: Go, Node, Python, the harness, a fake developer home                                            |
| `infra/`                            | One CDK app: the Checker (durable), the web function behind the HTTP API, the table, the bucket, the MicroVM image |

## Harness API

The Checker calls the harness over the MicroVM's HTTPS URL, with a
per-run bearer token the Checker passes at launch (see "The MicroVM" below
for how). The token is HMAC-SHA256 of the check's id under a key in Secrets
Manager (`RUN_TOKEN_SECRET_ARN`), so the Checker derives it again on every
invocation and no execution history keeps it. JSON in and out; every response carries
`observations` since the last call.

| Call                | Body                                                                                    | Answers                                                |
| ------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `POST /install`     | `{"kind":"go"\|"npm"\|"pypi"\|"remote","ref":"name@version or URL","allowHosts":[...]}` | install log, resolved dependency set and its SHA-256   |
| `POST /start`       | `{"command":[...]}` (empty: the kind's default)                                         | the server's `initialize` result                       |
| `POST /list`        | `{}`                                                                                    | tools (whole schemas), resources, prompts, as raw JSON |
| `POST /call`        | `{"tool":"name","arguments":{...}}`                                                     | the raw result                                         |
| `POST /allow`       | `{"hosts":[...]}`                                                                       | the egress allowlist now in force                      |
| `POST /clock`       | `{"offset":"720h"}`                                                                     | the fake clock now in force                            |
| `POST /source`      | `{"path":"dist/index.js"}`, relative to the installed package                           | `{"path","content"}`                                   |
| `POST /download`    | `{"path":"/home/dev/.cache/x"}`, a file the server wrote                                | `{"path","size","sha256","kind","excerpt"}`            |
| `GET /observations` |                                                                                         | all observations of the run                            |

The investigation's calls (`/call` again, `/source`, `/download`, `/clock`)
and `/allow` are best effort: an error answer is told to the judge, and the
check goes on.

An observation is `{"at","kind","detail"}`, where `kind` is one of `dns`
(every UDP datagram to port 53, at any address: name, type, answers,
`faked`, the canaries found anywhere in the datagram or in any question's
name, and `unanswered`: why it got no answer, when it isn't a query),
`connect` (a tunnel through the proxy: host, `serverName` (the TLS
SNI), port, `intercepted`, `allowed`, and the canaries in the CONNECT
request and server name; or direct traffic the firewall refused:
`via: "direct"`, `proto` (tcp, udp, icmp, …), address, port, the
canaries in a refused packet's payload or the first 64 KiB a refused TCP
connection sent, `unscanned` when that read was cut short, `more` on the
1000th, after which only traffic holding a canary is recorded, `dropped`
when the kernel lost packets unread, refused ones or datagrams to port
53, and `stopped` when the harness stopped reading refused packets or
DNS),
`http`
(method, host, path, `allowed`, the canaries found in it, as parsed and
as sent, trailer and chunk extensions included, with their encoding, and
`unscanned`: why part of it went unsearched, when it did; bytes the proxy
couldn't read as a request are an `http` observation of their own, with
the canaries in them and `unscanned`), `file` (path written), `sampling`, `elicitation`,
`process`, `hook` (a lifecycle hook called after `/run`: method, path,
caller, the status it got). Bodies are not returned, only what was found
in them.

## The MicroVM

What Lambda MicroVMs (`sandbox/Dockerfile`, `infra/sandbox.ts`,
`src/internal/checker/sandbox`) force on the harness:

- **One snapshot for every run.** Lambda builds the image, starts the
  harness once, and snapshots it; each check's MicroVM resumes from that
  snapshot. Environment variables are the image's, the same for every
  MicroVM, so the token can't come from `HARNESS_TOKEN`, and nothing
  made before the snapshot (a key, a seed, a planted home) may be per-run.
- **Two ports.** The Harness API listens on `PORT`, 8080, the endpoint's
  default. Lambda's lifecycle hooks are served on `HOOKS_PORT`, 9000. The
  Checker's endpoint tokens open 8080 only, so nobody holding one reaches
  a hook. Lambda forwards by port, never by path.
- **Hooks the harness serves on 9000**, under `/aws/lambda-microvms/runtime/v1/`:
  - `POST .../ready` at image build: 200 once the API listens (503 to be
    asked again). Lambda snapshots after it.
  - `POST .../run` when a MicroVM starts, with
    `{"microvmId":"mvm-...","runHookPayload":"<string>"}`. The payload is
    `{"token":"<run token>","canaries":[{"kind","value"}...]}` as JSON, at
    most 16 KB. The harness keeps the token, plants the home from the
    canaries, then answers 200; Lambda forwards no request before that, and
    gives the hook 30 seconds. Until then every Harness API call answers 503. A second `/run`, which only something inside the MicroVM can send,
    is refused with 409 and observed as a `hook`. The token and canaries are not repeated
    anywhere else: `/install`'s `canaries` field is no longer needed.
- **Headers.** Every request to the endpoint carries Lambda's
  `X-aws-proxy-auth` (a JWE token, an hour at most) and `X-aws-proxy-port`;
  Lambda removes `X-aws-proxy-*` before the harness sees the request, so
  the harness authenticates the `Authorization: Bearer <run token>` header
  only. A 403 or 502 without JSON is Lambda's, not the harness's.
- **Root, and nothing to climb back to it.** The image runs the harness
  as root (its `ENTRYPOINT`, `USER root`); Lambda documents nothing that
  stops that, and runs the container with the standard Linux capabilities,
  which include switching users. The image has no setuid or setgid file.
  Lambda offers no `no-new-privileges` switch for the container, so the
  harness sets it per process: the image ships `setpriv`
  (`setpriv --no-new-privs`). `libfaketime` is at
  `/usr/local/lib/faketime/libfaketime.so.1` for `POST /clock`.
- **No AWS credentials inside.** MicroVMs run with no execution role, so the
  server under test finds none, and Lambda keeps no runtime logs:
  observations come back through the API only.
- **Egress is all or nothing at Lambda's level.** A MicroVM gets the
  internet (`INTERNET_EGRESS`) or a VPC through a network connector; Lambda
  filters no host. Deny-by-default (the egress proxy, #5) is the harness's
  job inside the VM, and stopping a server that ignores the proxy needs the
  harness to own the network: iptables or a network namespace, which takes
  the image's `additionalOsCapabilities: ["ALL"]` (granted to root only,
  never to `dev`). The image asks for them since #5: the harness puts the
  firewall up for `dev`'s user ID before it answers `/ready`, and the
  proxy CA's certificate (never its key) is in `/etc/mcp-customs`.
- **Lifetime.** A MicroVM lives at most 2 hours, running and suspended
  (Lambda allows 8). A check waiting days for a person must have
  terminated its MicroVM first; suspend and resume are for pauses within
  the run.
- **Arm64.** The image is built for `ARM_64`, Lambda's default (x86_64
  exists from base image version 3); the harness binary is built for
  linux/arm64.

## Store

One DynamoDB table (`DYNAMODB_TABLE_NAME`), keys `pk` and `sk`:

| Item      | `pk`            | `sk`         | Holds                                                                |
| --------- | --------------- | ------------ | -------------------------------------------------------------------- |
| A check   | `CHECK#<id>`    | `META`       | the submission, status, verdict, durable execution ARN, callback ID  |
| A step    | `CHECK#<id>`    | `STEP#<seq>` | what ran, its findings, a one-line summary (the web page's timeline) |
| A verdict | `HASH#<sha256>` | `VERDICT`    | the approved check's ID, its tool-list hash, the install spec        |

A check's `status` is `running`, `waiting` (for a person's Approve or
Block, under its `callbackId`), `done` or `failed`. A `STEP#` item's `name`
is the registered action that ran (`resolve`, `lookup`, `install`, `list`,
`scan`, `probe`, `observe`, `ask_human`, `wait`, and the investigation's
`allow`, `call`, `read_source`, `inspect_download`, `clock`), or `start`,
`write_probes`, `judge`, `investigate` (one a turn: the move the judge
picked), `verdict` or `failed`. A check that fails ends its sandbox, writes a
`failed` step whose summary names the action that failed (never the
harness's or the SDK's text), and turns `failed`. A check writes its `verdict` step, then its report, its `HASH#` item
and, last, `done`: a `verdict` step that can't be written fails the check
with no `HASH#` item. A `HASH#` item is written only when a check passes by code or a
person approves it; its `installSpec` is the JSON
`{"kind","ref","dependencySha256","toolListSha256"}`.

A check's `META` also keeps `sandboxId`, the MicroVM its `resolve`
launched, written before anything else, so a failure can end it.

No step keeps more than 200 KB. What the install was seen doing, the
server's `initialize` result and its start, a tool list, a probe's answer
or the observations larger than that are kept whole in the bucket as
`observations/<check-id>-<what>.json` (`resolve`, `install`, `list`,
`call-<n>`, `observe`), and the check fails, with an `oversized` code
finding on its `failed` step.

No `STEP#` item is larger than DynamoDB's 400 KB, measured as the store
encodes it (`store.StepSize`, after JSON writes a control character as six
bytes): a step keeps at most 20 findings of each rule and 200 in all, each
rule cut to 64 bytes and its evidence to 512, and fewer when those would
take the item past 400 KB. It adds one finding per rule saying how many
more of that rule it left off past its 20, and one `more-findings` finding
counting the findings of any rule, kept or not, it left off once it had
kept its most (200, or as many as fit). The verdict is decided from every
finding, and the report keeps them all. Findings
name a tool by its place in the listing (`tool 3`, `the result of tool
3`), whichever step made them.

Reports go to the bucket as `reports/<check-id>.json`. Raw observations as
`observations/<check-id>.json`.

## A person's answer

The web function answers a `waiting` check by sending its `callbackId`
(`SendDurableExecutionCallbackSuccess`) the JSON
`{"decision":"approve"}` or `{"decision":"block"}`. Anything else, or no
answer within 7 days, leaves the verdict code decided.

## The judge

Claude on Amazon Bedrock (`JUDGE_MODEL_ID`, an inference profile the
Checker alone may call), through the Converse API, in three durable steps:
`write-probes`, `judge`, and `investigate-<n>`, one a turn, at most 8. Each
call answers through one tool whose JSON Schema is in
`src/internal/checker/judge_answers.go`; code decodes it with the same
limits and refuses anything else. Server text (the submission, tools,
resources, prompts, results, observations, each turn's outcome) is sent
between a line `<<<EVIDENCE <nonce> BEGIN <name>>>>` and
`<<<EVIDENCE <nonce> END <name>>>>`, the nonce fresh for every call, and the
system prompt names it evidence, never instructions. Model findings are
`purpose-mismatch`, `server-instructs-model`, `judge-concern` and
`judge-asked-for-a-person`, each at least review.

## Verdicts

`pass`, `review` or `block`, with `findings[]`, each
`{"source":"code"|"model","rule","evidence"}`. A `code` finding of a
blocking rule can't be outweighed by any `model` finding.
