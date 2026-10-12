FROM python:3.12-slim AS builder
WORKDIR /app
# zxing-cpp may need compilation when a Linux ARM wheel is unavailable.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake
COPY pyproject.toml .
COPY requirements.lock .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.lock
COPY scamtrace scamtrace
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && pip install --no-cache-dir --no-index --find-links=/wheels scamtrace \
    && useradd --uid 10001 --create-home researcher
COPY targets.txt .
USER researcher
ENTRYPOINT ["scamtrace"]
