# mail — a rug-pulled demo MCP server (malicious on purpose)

**This server is malicious by design. It is a test fixture for MCP Customs and
must only ever be run inside its sandbox, against fake secrets. Do not deploy
it or point a real agent at it.**

It demonstrates a _rug pull_: a server that is benign when first reviewed and
turns malicious in a later version whose tool list looks exactly the same. MCP
Customs catches it by running the server, not by reading `tools/list`.

## The tool

`send_email(to, subject, body)` — sends an email. The `tools/list` output is
**byte-identical** between the two builds below (a test pins the exact bytes),
so a scanner comparing tool lists sees no change across the "update".

## The two builds

- **`v1_0_0`** (the default build): delivers only to `to`, and reaches no
  network.
- **`v1_0_1`**: also blind-copies every message — the recipient's address, the
  subject and the body — to a fixed outside host, `mail-sink.example`, over an
  HTTPS `POST`. The host is a constant in the `v1_0_1` source, not read from
  the environment, so the whole difference from v1.0.0 is one file.

The copy carries the message's `to` field, so inside the sandbox the planted
canary address is seen leaving to a host the mail server had no reason to
reach, as the real [postmark-mcp](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails)
rug pull did. The delivery and copy transports sit behind the `sender` and
`copier` interfaces, so unit tests observe both without a network; the
copy's behaviour end to end, under the harness's egress proxy, is proved by
`TestTheMailDemosRugPullCopiesTheRecipientToAnOutsideSink` in
`src/internal/harness`.

## Running and testing

```
go run ./demo/mail                    # v1_0_0: delivers only to `to`
go run -tags v1_0_1 ./demo/mail       # v1_0_1: also copies to mail-sink.example

go test ./demo/mail/...               # v1_0_0 behaviour + identical tool list
go test -tags v1_0_1 ./demo/mail/...  # v1_0_1 copy behaviour + identical tool list
```

## Published versions

A deploy publishes the version of this demo `infra/demo-versions.json` names (v1.0.0 or v1.0.1), as the
module `github.com/JairJosafath/mcp-customs/demo/mail`, to the stack's own
Go module proxy (`src/internal/demoproxy`, docs/runbook.md, "The demo
proxy"). Each version's module holds the build for that version with its
build line taken off, so `go install ...@v1.0.1` builds the rug pull with
no tag.

`make check` builds and tests the default (v1_0_0). The v1_0_1 behaviour is
covered by a build-tagged test run with `-tags v1_0_1`, and end to end (root
only) by the harness e2e.
