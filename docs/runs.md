# Runs

One row per cloud session, for the comparison with theos's factory after
the deadline. Cost and tokens come from each session's own report.

| Issue | Role        | Session                          | Started (UTC)    | Rounds | Result                                                                                          | Cost        |
| ----- | ----------- | -------------------------------- | ---------------- | ------ | ----------------------------------------------------------------------------------------------- | ----------- |
| #1    | implementer | session_01SZoxcoQ45n8FzwzWA5zX3m | 2026-11-14 06:27 | 1      | PR #12, 15 min, 54 turns                                                                        | $4.63       |
| #2    | implementer | session_01SZoxcmkFxf7WSYg5oVCb1g | 2026-11-14 06:27 | 1      | PR #11, 10 min, 24 turns                                                                        | $2.14       |
| #3    | implementer | session_01SZoxckrbvfYLJDUiX6BUtp | 2026-11-14 06:27 | 1      | PR #13, 16 min, 41 turns; a safety stop moved it to an older model mid-run (malicious fixtures) | $6.33       |
| #1    | reviewer    | session_01SZoxcm4FA7P5krSuB4A7j1 | 2026-11-14 07:10 | 1      | approved (as a comment: same GitHub account); PR #12 merged 07:39                               | $1.43       |
| #2    | reviewer    | session_01SZoxcoquaRgfhouXQpNNz4 | 2026-11-14 07:10 | 1      | changes requested: SSH-key canary missed when trimmed, CRLF, in JSON, in wrapped base64         | $1.31       |
| #3    | reviewer    | session_01SZoxcmiK83boXzkrz52V8w | 2026-11-14 07:10 | 1      | approved; 2 safety stops moved it to an older model                                             | $1.73       |
| #2    | implementer | session_01SZoxcmkFxf7WSYg5oVCb1g | 2026-11-14 07:39 | 2      | SSH-key forms fixed, 12 new cases; PR #11 at 5bd029c                                            | $1.90       |
| #4    | implementer | session_01SZoxckcHTcgtbYQjWfJUD4 | 2026-11-14 07:39 | 1      | PR #16, 15 min, 46 turns                                                                        | $4.07       |
| #14   | implementer | session_01SZoxcnyK3xCTTbYFreeMPY | 2026-11-14 07:40 | 1      | PR #15, 9 min, 38 turns                                                                         | $2.74       |
| #3    | merge       |                                  | 2026-11-14 08:02 |        | PR #13 merged after a CI rerun on #12                                                           |             |
| #2    | reviewer    | session_01SZoxcnUwyrMYtCHMWAg78H | 2026-11-14 08:03 | 2      | approved; probed 50 fresh canary sets                                                           | $1.56       |
| #14   | reviewer    | session_01SZoxckwoDW5poMVaocbPMD | 2026-11-14 08:03 | 1      | approved                                                                                        | $1.10       |
| #4    | reviewer    | session_01SZoxcmGSt796rtTH2FMFAu | 2026-11-14 08:03 | 1      | changes requested: token readable via /proc when not root; secret-shaped fixtures               | $1.88       |
| #6    | implementer | session_01SZoxcpFFXBJjqYoP9MUAUW | 2026-11-14 08:04 | 1      | PR #17, stacked on #16; read AWS's MicroVM docs: build-time snapshot, no host filtering         | $6.38       |
| #4    | implementer | session_01SZoxckcHTcgtbYQjWfJUD4 | 2026-11-14 08:26 | 2      | root-only harness, fake fixtures, weather /start+/list test                                     |             |
| #2    | merge       |                                  | 2026-11-14 08:35 |        | PR #11 merged                                                                                   |             |
| #4    | reviewer    | session_01SZoxco8notiYfRyBXdqb7X | 2026-11-14 08:30 | 2      | approved; ran the binary under real users: no environ, memory, files or ptrace                  | $1.19       |
| #6    | reviewer    | session_01SZoxck91sAwsWMLUY6TQgw | 2026-11-14 08:36 | 1      | approved; checked AWS docs and pinned downloads                                                 | $1.83       |
| #14   | merge       |                                  | 2026-11-14 08:45 |        | PR #15 merged                                                                                   |             |
| #4    | merge       |                                  | 2026-11-14 08:54 |        | PR #16 merged                                                                                   |             |
| #6    | implementer | session_01SZoxcpFFXBJjqYoP9MUAUW | 2026-11-14 08:56 | 1      | merged main into the stacked branch after #16's squash (force-push refused)                     | $7.74 total |
| #6    | merge       |                                  | 2026-11-14 09:02 |        | PR #17 merged                                                                                   |             |
| #5    | implementer | session_01SZoxcp9PJnXuBnT5L4iVZW | 2026-11-14 08:54 | 1      |                                                                                                 |             |
| #19   | implementer | session_01SZoxcjzVQrVQHujG9T2Dpc | 2026-11-14 09:02 | 1      |                                                                                                 |             |
| #7    | implementer | session_01SZoxcoLDehQnWcuwQ7cUqj | 2026-11-14 09:02 | 1      |                                                                                                 |             |
