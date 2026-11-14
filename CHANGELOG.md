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

### Removed

- The items API theos scaffolded (`PUT` and `GET /items/{id}`) and its
  `Items` table.
