# Changelog

Every user-visible change, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): the `version` in `package.json`.

## [Unreleased]

### Added

- The web page and API: submit a pinned package or an https URL from the
  form on `/` or `POST /api/checks`, which start the Checker asynchronously
  and answer the check's ID (`400` with a message for bad input); watch a
  check's steps on `/checks/<id>` as they are written, then its verdict and
  report; Approve or Block a check waiting for a person with the reviewer key,
  which sends the Checker's durable callback; `GET /api/checks/<id>` answers
  the verdict as JSON, with the install spec for a pass. All text from a
  check is shown escaped, hidden characters as visible escapes, under a
  strict Content-Security-Policy.
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
