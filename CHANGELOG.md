# Changelog

Every user-visible change, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): the `version` in `package.json`.

## [Unreleased]

### Added

- The harness answers the judge's investigation (#27): `POST /clock`
  moves the server's clock forward with libfaketime, `POST /source` reads
  a file of the installed package (64 KB at most, nothing outside it),
  and `POST /download` describes a file the server was seen writing (size,
  SHA-256, kind and an excerpt). All three work after the seal and reopen
  no egress. `/clock` says whether the server's runtime sees the move (not
  a Go or static binary), and the judge is told.

- A re-check of an approved package never ends silently (#42). One that
  fails is started once more by the next poll, under a new check ID
  linked to the same approved check and version; a retry that fails too
  is shown on the approved check and raises the
  `RecheckFailedTwice-Critical` alarm. One that code does not pass marks
  the approved check superseded as soon as code decides, before a person
  is asked, shown on its page and as `supersededBy` in
  `GET /api/checks/<id>`, and puts an `Approved check superseded` event
  (source `mcp-customs`) on the account's default EventBridge bus; only
  the newest polled version's re-check sets the mark. A person who then
  approves it lifts the mark and an `Approved check no longer superseded`
  event goes out.
- `demo/record.ts` records the demo against a deployed stack: the weather
  server blocked with the SSH key seen leaving base64-encoded, the mail
  server's v1.0.0 passed and its v1.0.1 blocked, as a 1280×720 video under
  2:50 (#38). Each scene has its own budget and gives up when it runs out;
  `--scene` records one scene to its own file. `demo/script.md` is its narration and `docs/results.md` the
  write-up's skeleton. `src/cmd/webstub` serves the web page with a fake
  store and Checker, for the recorder's test; it is never deployed.
- The web stub plays the steps the Checker writes for each demo scene
  (`src/internal/demoscene`), and a Checker test runs each scene through
  the Checker with its fakes and fails on any difference, so the stub
  can't drift (#46): it now shows the `allow`, `seal` and last `observe`
  steps, tools numbered from 0, and the verdict's model findings. A scene
  that ends at another verdict fails with
  `scene <name>: expected <verdict>, got <verdict>`.

### Fixed

- Hidden text is read more closely (#33). Characters Unicode assigned
  after Go's tables (15.0), such as 🫩 U+1FAE9 and the newest CJK, are no
  longer `hidden-unassigned`. U+FE0E and U+FE0F are
  `hidden-variation-selector` unless they follow a character Unicode gives
  that variation sequence (after a digit, `#` or `*` only in a keycap,
  before U+20E3), so a run of them, one after a letter, or one on a bare
  digit is a finding. Control characters other than `\n`, `\t` and the `\r` of a
  `\r\n` (a lone CR, backspace, NUL, NEL and the rest) are the new
  `hidden-control-character`. The injection patterns read every Unicode
  space, line break and blank lookalike (U+2800, the Hangul fillers,
  U+1D159) as a space, with any combining mark on it left out, so
  `ignore` U+2800 `previous` U+2800 `instructions` is found.
- A pass's approval is written in one transaction with its check marked
  done (#33): when that write fails, the check fails with no `HASH#` or
  `APPROVED` item left behind, so a later check of the same dependency set
  is not passed as seen before. A check marked done stays done: a failure
  after it is never recorded as `failed` over it, and a pass's lift of a
  superseded mark, or its event, that fails is logged instead.
- A server the sandbox can't install ends at review, decided by code,
  with an `install-failed` finding naming what failed, instead of failing
  the check (#39). A PyPI dependency only an sdist ships fails the
  install with a log line naming it, as its build dependencies can't be
  pinned; a blank line in pip's set no longer panics the harness, and a
  harness that can't end what an install step left running fails the step.

- The sandbox's egress proxy refuses a connection to a name that resolves
  to an address inside a network: loopback, link-local, private, shared or
  the instance metadata, so a wildcard-DNS name such as
  `169.254.169.254.nip.io` or `localtest.me` reaches none of them (#32).
  The Checker's Bedrock client tries each call once, under the judge's own
  retries, so a busy model is no longer tried up to twelve times.
- An install's GET of the demo Go proxy must be `https` on port 443, as
  its `/goproxy/` prefix is (#61). A plain-http GET under the prefix, or
  one to any other port, is refused and recorded like any other request
  the sandbox may not send.
- The stack's own API is kept out by fixed rules (#56). The Checker's
  refusal compares against API Gateway's published ranges for the region,
  so it no longer changes from run to run, and refuses the API's FIPS and
  dual-stack names too. The harness refuses to start without `API_HOST`,
  refuses IP addresses in `/allow` and `/install` with 400, and ends an
  install's registry access even when the installer panics; its egress
  proxy refuses any connection to the API's addresses, DNS rebinding
  included, but for an install's GET of the demo Go proxy. Every layer
  allows only plain ASCII host names, so a soft hyphen, an ideographic
  full stop, a fullwidth letter or punycode can't spell the API's name.
- The server under test can never be allowed to reach MCP Customs' own
  API (#53). The Checker refuses an allowlist holding the stack's API host,
  or a name that resolves to it, as an `allow-own-api` code finding that
  ends the investigation at review; the harness's `POST /allow` refuses
  the same host with 403.
- A seal or last read that works but whose step can't be written ends
  at review with `step-not-recorded`, not `not-sealed` (which said egress
  stayed open) and not a failed check (#48). A seal or last read that
  fails still gives `not-sealed`.
- The harness finds `iptables` and `ip6tables`: the MicroVM image's PATH
  now has `/usr/sbin`, where Amazon Linux 2023 keeps them, so the firewall
  comes up (#20). The image's base is pinned by digest, dnf to the base's
  release and each package's version, Python to 3.13.18, and its build
  fails without anything the harness needs to start. The build role trusts
  Lambda only for this account's image. A harness answer over 16 MiB is
  reported as too large (`ErrTooLarge`), not as one without JSON.
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

- The stack serves the demo servers' versions itself, as a Go module proxy
  at `GET /goproxy/...` read from its bucket, so the live rug pull needs no
  account on a public registry (#40). A deploy publishes the versions
  `infra/demo-versions.json` names, v1.0.0 for both demos as committed;
  setting `"mail": "v1.0.1"` there and deploying publishes the mail demo's
  rug pull, a module whose default build is v1.0.1, and the poller starts
  the re-check.
  `make demo-build` writes the same files without AWS. `GO_PROXY_URL` is
  now a GOPROXY-style list, the stack's demo proxy and then the public
  one, for the poller and the sandbox's `go install`, which skips the
  checksum database for the demo modules alone and may only GET the
  stack's API under `/goproxy/`.

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
