FROM python:3.15-slim
LABEL io.modelcontextprotocol.server.name="io.github.probityai/agent-evidence-mcp"
LABEL org.opencontainers.image.source="https://github.com/probityai/agent-evidence-mcp"
LABEL org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
USER nobody
ENTRYPOINT ["agent-evidence-mcp"]
