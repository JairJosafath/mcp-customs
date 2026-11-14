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
per-run bearer token the Checker generates and passes at launch (see "The
MicroVM" below for how). JSON in and out; every response carries
`observations` since the last call.

| Call                | Body                                                                                                     | Answers                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `POST /install`     | `{"kind":"go"\|"npm"\|"pypi"\|"remote","ref":"name@version or URL","canaries":[...],"allowHosts":[...]}` | install log, resolved dependency set and its SHA-256   |
| `POST /start`       | `{"command":[...]}` (empty: the kind's default)                                                          | the server's `initialize` result                       |
| `POST /list`        | `{}`                                                                                                     | tools (whole schemas), resources, prompts, as raw JSON |
| `POST /call`        | `{"tool":"name","arguments":{...}}`                                                                      | the raw result                                         |
| `POST /allow`       | `{"hosts":[...]}`                                                                                        | the egress allowlist now in force                      |
| `POST /clock`       | `{"offset":"720h"}`                                                                                      | the fake clock now in force                            |
| `GET /observations` |                                                                                                          | all observations of the run                            |

An observation is `{"at","kind","detail"}`, where `kind` is one of `dns`,
`connect`, `http` (method, host, path, and the canaries found in it, with
their encoding), `file` (path written), `sampling`, `elicitation`,
`process`. Bodies are not returned, only what was found in them.

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
    gives the hook 30 seconds. The token and canaries are not repeated
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
  never to `dev`). The image asks for none until #5 needs them.
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
`scan`, `probe`, `observe`, `ask_human`, `wait`), or `start`, `judge` or
`verdict`. A `HASH#` item is written only when a check passes by code or a
person approves it; its `installSpec` is the JSON
`{"kind","ref","dependencySha256","toolListSha256"}`.

Reports go to the bucket as `reports/<check-id>.json`. Raw observations as
`observations/<check-id>.json`.

## A person's answer

The web function answers a `waiting` check by sending its `callbackId`
(`SendDurableExecutionCallbackSuccess`) the JSON
`{"decision":"approve"}` or `{"decision":"block"}`. Anything else, or no
answer within 7 days, leaves the verdict code decided.

## Verdicts

`pass`, `review` or `block`, with `findings[]`, each
`{"source":"code"|"model","rule","evidence"}`. A `code` finding of a
blocking rule can't be outweighed by any `model` finding.
