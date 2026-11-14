# Changelog

Every user-visible change, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/): the `version` in `package.json`.

## [Unreleased]

### Added

- The Checker, a Lambda durable function (`src/cmd/checker`), which for now
  records a check as `running` and its first step; the web function
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
