FROM node:22-bookworm-slim
WORKDIR /fixture
COPY fixtures/containment/ /fixture/
RUN chmod -R a-w /fixture
USER 65532:65532
ENTRYPOINT ["node"]
