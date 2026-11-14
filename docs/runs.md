# Runs

One row per cloud session, for the comparison with theos's factory after
the deadline. Cost and tokens come from each session's own report.

| Issue | Role        | Session                          | Started (UTC)    | Rounds | Result                                                                                          | Cost         |
| ----- | ----------- | -------------------------------- | ---------------- | ------ | ----------------------------------------------------------------------------------------------- | ------------ |
| #1    | implementer | session_01SZoxcoQ45n8FzwzWA5zX3m | 2026-11-14 06:27 | 1      | PR #12, 15 min, 54 turns                                                                        | $4.63        |
| #2    | implementer | session_01SZoxcmkFxf7WSYg5oVCb1g | 2026-11-14 06:27 | 1      | PR #11, 10 min, 24 turns                                                                        | $2.14        |
| #3    | implementer | session_01SZoxckrbvfYLJDUiX6BUtp | 2026-11-14 06:27 | 1      | PR #13, 16 min, 41 turns; a safety stop moved it to an older model mid-run (malicious fixtures) | $6.33        |
| #1    | reviewer    | session_01SZoxcm4FA7P5krSuB4A7j1 | 2026-11-14 07:10 | 1      | approved (as a comment: same GitHub account); PR #12 merged 07:39                               | $1.43        |
| #2    | reviewer    | session_01SZoxcoquaRgfhouXQpNNz4 | 2026-11-14 07:10 | 1      | changes requested: SSH-key canary missed when trimmed, CRLF, in JSON, in wrapped base64         | $1.31        |
| #3    | reviewer    | session_01SZoxcmiK83boXzkrz52V8w | 2026-11-14 07:10 | 1      | approved; 2 safety stops moved it to an older model                                             | $1.73        |
| #2    | implementer | session_01SZoxcmkFxf7WSYg5oVCb1g | 2026-11-14 07:39 | 2      | SSH-key forms fixed, 12 new cases; PR #11 at 5bd029c                                            | $1.90        |
| #4    | implementer | session_01SZoxckcHTcgtbYQjWfJUD4 | 2026-11-14 07:39 | 1      | PR #16, 15 min, 46 turns                                                                        | $4.07        |
| #14   | implementer | session_01SZoxcnyK3xCTTbYFreeMPY | 2026-11-14 07:40 | 1      | PR #15, 9 min, 38 turns                                                                         | $2.74        |
| #3    | merge       |                                  | 2026-11-14 08:02 |        | PR #13 merged after a CI rerun on #12                                                           |              |
| #2    | reviewer    | session_01SZoxcnUwyrMYtCHMWAg78H | 2026-11-14 08:03 | 2      | approved; probed 50 fresh canary sets                                                           | $1.56        |
| #14   | reviewer    | session_01SZoxckwoDW5poMVaocbPMD | 2026-11-14 08:03 | 1      | approved                                                                                        | $1.10        |
| #4    | reviewer    | session_01SZoxcmGSt796rtTH2FMFAu | 2026-11-14 08:03 | 1      | changes requested: token readable via /proc when not root; secret-shaped fixtures               | $1.88        |
| #6    | implementer | session_01SZoxcpFFXBJjqYoP9MUAUW | 2026-11-14 08:04 | 1      | PR #17, stacked on #16; read AWS's MicroVM docs: build-time snapshot, no host filtering         | $6.38        |
| #4    | implementer | session_01SZoxckcHTcgtbYQjWfJUD4 | 2026-11-14 08:26 | 2      | root-only harness, fake fixtures, weather /start+/list test                                     |              |
| #2    | merge       |                                  | 2026-11-14 08:35 |        | PR #11 merged                                                                                   |              |
| #4    | reviewer    | session_01SZoxco8notiYfRyBXdqb7X | 2026-11-14 08:30 | 2      | approved; ran the binary under real users: no environ, memory, files or ptrace                  | $1.19        |
| #6    | reviewer    | session_01SZoxck91sAwsWMLUY6TQgw | 2026-11-14 08:36 | 1      | approved; checked AWS docs and pinned downloads                                                 | $1.83        |
| #14   | merge       |                                  | 2026-11-14 08:45 |        | PR #15 merged                                                                                   |              |
| #4    | merge       |                                  | 2026-11-14 08:54 |        | PR #16 merged                                                                                   |              |
| #6    | implementer | session_01SZoxcpFFXBJjqYoP9MUAUW | 2026-11-14 08:56 | 1      | merged main into the stacked branch after #16's squash (force-push refused)                     | $7.74 total  |
| #6    | merge       |                                  | 2026-11-14 09:02 |        | PR #17 merged                                                                                   |              |
| #5    | implementer | session_01SZoxcp9PJnXuBnT5L4iVZW | 2026-11-14 08:54 | 1      | stopped after a safety stop with no tests; replaced                                             |              |
| #19   | implementer | session_01SZoxcjzVQrVQHujG9T2Dpc | 2026-11-14 09:02 | 3      | PR #21: /ready and /run hooks; absolute command paths; PyPI forgery moved to #23                |              |
| #7    | implementer | session_01SZoxcoLDehQnWcuwQ7cUqj | 2026-11-14 09:02 | 3      | PR #22: fixed checks, registry, interpreter; unbounded results moved to #25                     |              |
| #19   | reviewer    | session_01SZoxcjdUMr8AK5udQ688az | 2026-11-14 09:24 | 1      | changes requested: harness resolved cat/go via PATH, a planted binary could forge the lockfile  |              |
| #7    | reviewer    | session_01SZoxcojbpN7P7n5mtiRiY3 | 2026-11-14 09:39 | 1      | changes requested: failed /install left the run running                                         |              |
| #19   | reviewer    | session_01SZoxcndJma9DEe69HRvUVM | 2026-11-14 09:43 | 2      | changes requested: pip console script forges the dependency listing                             |              |
| #19   | reviewer    | session_01SZoxcmuLQDTLxvCib4DqNH | 2026-11-14 10:00 | 3      | changes requested: PyPI hash pinning; predates the PR, moved to #23, merged                     |              |
| #7    | reviewer    | session_01SZoxcoS9q4f28rj6Xe1Jyp | 2026-11-14 10:05 | 2      | changes requested: steps over 256 KB hang the check                                             |              |
| #7    | reviewer    | session_01SZoxcpDyt3DyakF7oEt27r | 2026-11-14 10:19 | 3      | changes requested: unbounded initialize and file watch; no false pass, moved to #25, merged     |              |
| #5    | implementer | session_01SZoxcofYFHCQqBNFB7XDxX | 2026-11-14 10:25 | 2      | PR #24: egress proxy, TLS interception, DNS, NFLOG; replies posted by the orchestrator          |              |
| #5    | reviewer    | session_01SZoxcoev38y5uCvTFYpbbX | 2026-11-14 10:43 | 1      | seven gaps incl. gzip and 8 MiB body skips                                                      |              |
| #8    | implementer | session_01SZoxcnGpUQTXoFy8J9iNZa | 2026-11-14 10:52 | 2      | PR #29: Bedrock judge, probes, investigation loop                                               | $10.84 total |
| #9    | implementer | session_01SZoxcox2SePvKDp8fT2Bvk | 2026-11-14 10:52 | 3      | PR #28: web page and API; round 3 merged main and fixed publicHost and U+2800                   | $8.62 total  |
| #25   | implementer | session_01SZoxckuvLomwNjpBL3aM7S | 2026-11-14 10:52 | 1      | PR #26: step and store bounds                                                                   |              |
| #8    | reviewer    | session_01SZoxcoMoQ6cVHriyYP3LZ6 | 2026-11-14 11:14 | 1      | changes requested: host-name allowlist, block verdict could be lost, no Bedrock retry           |              |
| #9    | reviewer    | session_01SZoxcoH2uUPLG3UdAWiDa2 | 2026-11-14 11:14 | 1      | changes requested: invisible and bidi Unicode shown raw                                         |              |
| #25   | reviewer    | session_01SZoxcmy9MiWgKqswxhDqDd | 2026-11-14 11:14 | 1      | approved; item size and write order moved to #30; PR #26 merged                                 |              |
| #5    | reviewer    | session_01SZoxcop4TvQH9B7B4nWh3s | 2026-11-14 11:28 | 2      | changes requested: canaries past the 1000-record cap unseen; NFLOG drops silent under load      | $2.60        |
| #30   | implementer | session_01SZoxckMnKnUHAqbe94j31W | 2026-11-14 11:32 | 1      | PR #31: invisible characters, STEP# bounded by stored size, verdict before done                 |              |
| #9    | reviewer    | session_01SZoxckD3xvmJdK5tXswxzS | 2026-11-14 11:37 | 2      | approved; publicHost zone and %-encoding bypass, U+2800 (non-blocking)                          | $2.05        |
| #8    | reviewer    | session_01SZoxcmsfCnksFbtfG6uPS9 | 2026-11-14 11:39 | 2      | approved; wildcard-DNS names, unreached backup checks, stacked retries moved to #32             | $1.68        |
| #8    | merge       |                                  | 2026-11-14 11:50 |        | PR #29 merged                                                                                   |              |
| #30   | reviewer    | session_01SZoxcnGPwE9WEPmDdzbm4C | 2026-11-14 11:51 | 1      | running                                                                                         |              |
| #9    | merge       |                                  | 2026-11-14 12:03 |        | PR #28 merged                                                                                   |              |
| #5    | implementer | session_01SZoxcofYFHCQqBNFB7XDxX | 2026-11-14 12:04 | 3      | round 3: B1 cap, B2 NFLOG drops                                                                 |              |
