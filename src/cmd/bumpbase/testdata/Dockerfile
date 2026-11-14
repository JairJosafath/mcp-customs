# The base, pinned by digest: the manifest list of al2023-minimal.2026.11.05.18,
# Amazon Linux 2023 release 2023.12.20261102.
FROM public.ecr.aws/lambda/microvms:al2023-minimal.2026.11.05.18@sha256:3e45d46e969eb0d34ea954aff12747e15ca3f4a594788812c7218445777fa4bc
ARG AL2023_RELEASE=2023.12.20261102

RUN echo "${AL2023_RELEASE}" > /etc/dnf/vars/releasever \
    && dnf install -y --setopt=install_weak_deps=False \
      ca-certificates-2025.2.76-1.0.amzn2023.0.5 findutils-1:4.8.0-2.amzn2023.0.2 \
      git-2.50.1-1.amzn2023.0.1 tar-2:1.34-1.amzn2023.0.4 \
    && dnf clean all

RUN dnf install -y --setopt=install_weak_deps=False gcc-11.5.0-5.amzn2023.0.5 make-1:4.3-5.amzn2023.0.2 \
    && dnf remove -y gcc make
