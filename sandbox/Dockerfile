# The MicroVM image: the harness and the toolchains a server under test
# installs with. Lambda MicroVMs builds it on its ARM64 base image from a zip
# the stack makes (infra/sandbox.ts): this file, and `harness`, which is
# src/cmd/harness built by `make synth` for linux/arm64. Lambda then starts
# the harness and snapshots it; every check's MicroVM resumes from that
# snapshot, so nothing here may hold a per-run value: the run's token and
# canaries arrive later, through the /run hook (docs/contracts.md).
FROM public.ecr.aws/lambda/microvms:al2023-minimal

# Pinned toolchains, checked against the checksums their publishers list.
ARG GO_VERSION=1.27.4
ARG GO_SHA256=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09
ARG UV_VERSION=0.13.8
ARG UV_SHA256=74f2f5c6024d397481db228db8fc25eed420db192243f88438c118e7e013e585
ARG PYTHON_VERSION=3.13
ARG LIBFAKETIME_VERSION=v0.9.13
ARG LIBFAKETIME_COMMIT=86b37fde2fed7336ea2d0c17928e3015a55d9b4a

# util-linux gives the harness `setpriv`, which starts the server under test
# with no_new_privs set. iptables-nft gives it the firewall that holds the
# server's traffic to the egress proxy.
RUN dnf install -y --setopt=install_weak_deps=False \
      ca-certificates findutils git gzip iptables-nft shadow-utils tar util-linux xz \
    && dnf clean all

# libfaketime, for the fake clock (POST /clock): the server under test is
# run with it preloaded. Built from the tag, checked against its commit;
# the compiler goes again in the same layer.
RUN dnf install -y --setopt=install_weak_deps=False gcc make \
    && git clone --quiet --depth 1 --branch "${LIBFAKETIME_VERSION}" https://github.com/wolfcw/libfaketime /tmp/libfaketime \
    && test "$(git -C /tmp/libfaketime rev-parse HEAD)" = "${LIBFAKETIME_COMMIT}" \
    && make -C /tmp/libfaketime PREFIX=/usr/local install \
    && rm -rf /tmp/libfaketime \
    && dnf remove -y gcc make \
    && dnf clean all \
    && test -f /usr/local/lib/faketime/libfaketime.so.1

# Go, for `go install module@version`.
RUN curl -fsSLo /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# Node and npm, for `npm install package@version`.
RUN curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-arm64.tar.xz" \
    && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && mkdir -p /usr/local/node \
    && tar -C /usr/local/node --strip-components=1 -xJf /tmp/node.tar.xz \
    && rm /tmp/node.tar.xz

# uv, and a current Python it installs as /usr/local/bin/python3 (the
# harness makes its venvs with `python3 -m venv`). The system's python3 in
# /usr/bin stays for dnf.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_PYTHON_BIN_DIR=/usr/local/bin
RUN curl -fsSLo /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-aarch64-unknown-linux-gnu.tar.gz" \
    && echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c - \
    && tar -C /usr/local/bin --strip-components=1 -xzf /tmp/uv.tar.gz \
    && rm /tmp/uv.tar.gz \
    && uv python install --default "${PYTHON_VERSION}" \
    && chmod -R a+rX /opt/uv

ENV PATH=/usr/local/bin:/usr/local/go/bin:/usr/local/node/bin:/usr/bin:/bin

# The unprivileged developer the server under test runs as. Its home is
# filled with the run's canaries when the run starts.
RUN useradd --create-home --uid 1000 --shell /bin/bash dev \
    && mkdir -p /home/dev/projects/server \
    && chown -R dev:dev /home/dev/projects

# The harness must run as root (it refuses otherwise: a non-root harness
# would let the server under test read its token from /proc), so it can switch to `dev` and keep its own files
# out of dev's reach; only root may write it.
COPY harness /usr/local/sbin/harness
RUN chown root:root /usr/local/sbin/harness && chmod 0755 /usr/local/sbin/harness

# No setuid or setgid file anywhere: nothing the server under test runs can
# raise its privileges back to root. The build fails if one is left.
RUN find / -xdev -type f -perm /6000 -exec chmod ug-s {} + \
    && test -z "$(find / -xdev -type f -perm /6000)"

# The Harness API on 8080, the endpoint's default port; Lambda's lifecycle
# hooks on 9000, a port no token the Checker makes opens.
ENV PORT=8080 \
    HOOKS_PORT=9000 \
    HARNESS_USER=dev
EXPOSE 8080 9000
USER root
ENTRYPOINT ["/usr/local/sbin/harness"]
