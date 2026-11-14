# Changelog

Every user-visible change, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): the `version` in `package.json`.

## [Unreleased]

### Fixed

- Nothing leaves the sandbox after the Checker's last read of its
  observations: once the investigation ends, the Checker seals egress
  (`POST /seal`: the allowlist emptied for good, every new tunnel
  refused, requests still being sent on cut), reads the observations a
  last time, and only then ends the sandbox; the verdict is decided from
  that read. A canary sent at the end, even to a host the judge allowed,
  is found. A seal or last read that fails gives `not-sealed`, at least
  review. `/allow` after the seal answers 409.
- No canary leaves the sandbox unseen through UDP port 53, an HTTP
  trailer or raw TCP: every datagram to port 53 is recorded and searched
  whole, query or not (`unanswered` says why one got no answer); a chunked
  request's trailer is searched; the first 64 KiB a refused TCP
  connection sends is searched before it is reset; and if the harness
  stops reading refused packets, a `connect {via: direct, stopped}`
  observation gives `direct-traffic-unrecorded`, at least review.
- What the egress proxy can't read fails closed: a burst to port 53 is
  held in a 64 MiB buffer and any datagram the kernel drops is recorded
  (`dropped`, `direct-traffic-unrecorded`); every byte sent to the proxy
  is searched as sent, so a chunk extension, an oversized or malformed
  header, a body cut short and bytes that aren't HTTP are found, and what
  it couldn't read as a request gives `body-not-scanned`; a tunnel's TLS
  server name is recorded (`serverName`) and searched; a refused TCP
  connection whose read was cut short, or that came while 64 others were
  being read, gives `body-not-scanned`; and a DNS reader that stops is
  recorded as the NFLOG reader is.
- A tunnel's whole TLS handshake is searched as sent, so a token in ALPN,
  the session ID or any extension is found, and an encrypted ClientHello
  gives `body-not-scanned`; a request body held open is recorded, as read
  so far and unscanned, when the proxy's 30-second read timeout ends it.
- The dependency set a check reports and hashes is the resolver's, not what
  the package says of itself (#23). For PyPI it is pip's `--dry-run`
  report, taken in a clean venv before anything is installed, as pinned
  requirements with each file's SHA-256, which pip then installs with
  `--no-deps --require-hashes`; a wheel that plants `.dist-info` files can
  no longer add, change or rename packages in it, and what the venv claims
  beyond the set is noted in the install log. For npm the lockfile is
  resolved with `--package-lock-only --ignore-scripts` and read before
  `npm ci` runs any script. Every process of the unprivileged account is
  killed after each install step. A PyPI submission seen before now takes
  the "seen before" shortcut like any other.

- Every character a person can't see is a code finding of a check, with its
  escaped form as evidence: besides ANSI escapes, tag, zero-width and bidi
  characters, now every default-ignorable code point
  (`hidden-default-ignorable`, and the Mongolian variation selectors as
  `hidden-variation-selector`), every other format character such as the
  interlinear annotation characters (`hidden-format-character`), the line
  and paragraph separators (`hidden-line-separator`), private use
  (`hidden-private-use`) and every unassigned code point
  (`hidden-unassigned`). Each gives at least review.
- A step's record is bounded by its size as stored, so findings whose text
  JSON grows, such as control characters, still fit DynamoDB's 400 KB: the
  step keeps as many as fit and counts the rest in `more-findings`.
- A check writes its `verdict` step before it reads `done`: a verdict step
  that can't be written fails the check, with no approval left behind.

### Added

- Re-checks of new versions: every five minutes a schedule asks the registry
  of each approved npm, Go or PyPI package for its latest version and starts
  a check of a new one, linked to the approved check. A re-check is probed in
  full even when its tool list matches the approved one, so a rug pull such
  as the demo mail server's v1.0.1 ends at block when the canary address
  leaves. The demo mail server's v1.0.1 now carries out that rug pull for
  real: it blind-copies every message, the recipient's address included, to
  a fixed outside host over HTTPS, so the egress proxy sees the planted
  address leave; its tool list stays byte-identical to v1.0.0's. The check page and `GET /api/checks/<id>` show `recheckOf`, the
  check that approved the earlier version. The registries are settings
  (`NPM_REGISTRY_URL`, `GO_PROXY_URL`, `PYPI_URL`) with the public ones as
  defaults.
- The web page and API: submit a pinned package or an https URL from the
  form on `/` or `POST /api/checks`, which start the Checker asynchronously
  and answer the check's ID (`400` with a message for bad input); watch a
  check's steps on `/checks/<id>` as they are written, then its verdict and
  report; Approve or Block a check waiting for a person with the reviewer key,
  which sends the Checker's durable callback; `GET /api/checks/<id>` answers
  the verdict as JSON, with the install spec for a pass. All text from a
  check is shown escaped, every invisible character as a visible escape,
  under a strict Content-Security-Policy. A remote URL must name a public
  host; a second decision, or one for a check no longer waiting, answers
  `409`.
- The judge: Claude on Amazon Bedrock, through the Converse API and a JSON
  Schema tool, in place of the stub. It writes each tool's probe arguments
  from its schema and description, planting the run's canaries where a
  secret fits (code keeps only what the schema allows); judges whether the
  server's behaviour fits its stated purpose and whether its text instructs
  the model; names the hosts the purpose needs, which become the sandbox's
  egress allowlist; and investigates, one registered action a turn (call a
  tool again, read a source file, inspect a download, move the clock, ask a
  person), at most 8 turns, each a durable step. Server text reaches it only
  fenced between marker lines unique to the call. A judge error, an answer
  outside its schema or running out of turns gives review; its findings go
  through `verdict.Decide` and only make a verdict stricter. The Checker may
  call only that model.

- The Checker runs a whole check without a model: it resolves and installs
  the server in its sandbox, looks up an approved verdict by the hash of the
  whole resolved dependency set, passes a dependency set and tool list seen
  before after `resolve`, `lookup` and `list` alone, and otherwise installs,
  lists, scans all server text, probes each tool, reads the observations and
  decides the verdict by code; a verdict short of pass waits up to a week for
  a person's Approve or Block. Each step is a `STEP#` item with a one-line
  summary; the report and observations go to the bucket, an approval to
  `HASH#`. A check waiting for a person has the status `waiting`; a
  check that fails ends its sandbox, says in a `failed` step which action
  failed, and has the status `failed`. A listed tool that can't be probed is
  a finding a person reviews. Each check's sandbox token is derived from a
  key in Secrets Manager, so no execution's history keeps it.
  A tool list, probe answer or set of observations over 200 KB is kept
  whole in the bucket and fails the check with an `oversized` finding.
  So are what the install was seen doing, and the server's `initialize`
  result and start, over the same bound. A step's record keeps at most 20
  findings of each rule and counts the rest, so a server with many
  findings still gets its verdict; and every finding names a tool by its
  place in the listing.
- The Checker, a Lambda durable function (`src/cmd/checker`); the web function
  (`src/cmd/web`), which serves `GET /` and `GET /api/health`, open to the
  public; the shared store of checks, steps and verdicts
  (`src/internal/store`); and a bucket for reports, in one stack.
- The sandbox's Lambda MicroVM image (`sandbox/Dockerfile`: Go, Node,
  Python with uv, the harness as root and an unprivileged `dev` user),
  built from a zip the stack makes, and the Checker's permission to launch,
  call, suspend, resume and terminate MicroVMs of it; the Checker's client
  for them (`src/internal/checker/sandbox`), with a fake for tests.
- The egress proxy (`src/internal/egress`): the server under test goes
  through the harness, which logs its DNS as `dns` observations and fakes
  TXT and A answers for unknown names; intercepts its TLS with a CA whose
  key never leaves the harness's memory; passes hosts on the run's
  allowlist (`POST /allow`, and `/install`'s `allowHosts`) and answers the
  rest with a fake 200; and records each request as an `http` observation
  with the run's canaries found in it, and their encoding, gzip and
  deflate bodies decoded first. A firewall (iptables, on the server's
  user) refuses all direct traffic, IPv6 included, and records each
  refused connection or packet (through NFLOG) as a `connect`, with the
  canaries in its payload. The package registries are reachable only
  while `/install` runs. A run records up to 1000 refused connections or
  packets, then only those holding a canary. Three new code findings give
  at least review: `tls-not-intercepted` (a client that refused the
  proxy's CA, to a host not allowed), `body-not-scanned` (a body over
  8 MiB, or in an encoding the proxy can't decode) and
  `direct-traffic-unrecorded` (more refused traffic than a run records,
  or packets the kernel dropped before the harness read them). The MicroVM image asks for
  `additionalOsCapabilities: ["ALL"]` and ships iptables for it.

### Changed

- The harness starts with no per-run value, as Lambda MicroVMs snapshot it
  at image build: it serves the `/ready` and `/run` lifecycle hooks on
  `HOOKS_PORT` (9000), takes the run's token and canaries from `/run`'s
  payload, exactly once, and plants the developer's home then. Until
  `/run`, every Harness API call answers `503`; `/install` no longer takes
  `canaries`, and `HARNESS_TOKEN` is gone. A hook called after `/run` is
  observed as a `hook`. The server under test and its install start
  through `setpriv --no-new-privs`, with a PATH of their own.
- A check is created once: a second create of the same check is refused,
  and its status, verdict and callback ID change only by an update of
  those fields.
- A `404` repeats at most 100 characters of the path asked for.
- Deleting the development stack empties and deletes its reports bucket;
  production still keeps it.

### Removed

- The items API theos scaffolded (`PUT` and `GET /items/{id}`) and its
  `Items` table.
