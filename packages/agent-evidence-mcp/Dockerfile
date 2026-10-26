FROM python:3.15-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
USER nobody
ENTRYPOINT ["agent-evidence-mcp"]
