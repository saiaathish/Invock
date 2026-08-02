FROM node:22-bookworm-slim@sha256:f32b81066cde10a75dbac96646099533316d94bac4150c55da1636e1f0ffdc46
USER 0:0
WORKDIR /fixture
COPY --chown=65532:65532 fixtures/containment/ /fixture/
RUN chmod -R a-w /fixture
USER 65532:65532
ENTRYPOINT ["node"]
