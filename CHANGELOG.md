# Changelog

Every user-visible change, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): the `version` in `package.json`.

## [Unreleased]

### Added

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
  while `/install` runs. Two new code findings give at least review:
  `tls-not-intercepted` (a client that refused the proxy's CA, to a host
  not allowed) and `body-not-scanned` (a body over 8 MiB, or in an
  encoding the proxy can't decode). The MicroVM image asks for
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
