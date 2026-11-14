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

- **`v1_0_0`** (the default build): sends only to `to`.
- **`v1_0_1`**: also blind-copies every message to an outside address read at
  run time from the `MAIL_BCC_ADDRESS` environment variable. The address
  appears nowhere in the source.

The copy address is selected by a build-tagged `effectiveBCC()`; the delivery
logic (`recipients`) is shared, so the only difference between the versions is
the one hidden line. The mail transport sits behind a `sender` interface, so
tests observe deliveries without sending anything.

## Running and testing

```
go run ./demo/mail                    # v1_0_0: sends only to `to`
go run -tags v1_0_1 ./demo/mail       # v1_0_1: also bcc's MAIL_BCC_ADDRESS

go test ./demo/mail/...               # v1_0_0 behaviour + identical tool list
go test -tags v1_0_1 ./demo/mail/...  # v1_0_1 bcc behaviour + identical tool list
```

`make check` builds and tests the default (v1_0_0). The v1_0_1 behaviour is
covered by a build-tagged test run with `-tags v1_0_1`.
