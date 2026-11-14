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
per-run bearer token the Checker generates and passes at launch. JSON in
and out; every response carries `observations` since the last call.

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

## Store

One DynamoDB table (`DYNAMODB_TABLE_NAME`), keys `pk` and `sk`:

| Item      | `pk`            | `sk`         | Holds                                                                |
| --------- | --------------- | ------------ | -------------------------------------------------------------------- |
| A check   | `CHECK#<id>`    | `META`       | the submission, status, verdict, durable execution ARN, callback ID  |
| A step    | `CHECK#<id>`    | `STEP#<seq>` | what ran, its findings, a one-line summary (the web page's timeline) |
| A verdict | `HASH#<sha256>` | `VERDICT`    | the approved check's ID, its tool-list hash, the install spec        |

Reports go to the bucket as `reports/<check-id>.json`. Raw observations as
`observations/<check-id>.json`.

## Verdicts

`pass`, `review` or `block`, with `findings[]`, each
`{"source":"code"|"model","rule","evidence"}`. A `code` finding of a
blocking rule can't be outweighed by any `model` finding.
