# Hugging Face Space build: fetches the tagged source and the trained artefacts from the GitHub
# release (artefacts are never committed to git), verifies them, and serves the app on port 7860.
FROM python:3.12-slim
ARG REF=v0.2.0
ARG REPO=https://github.com/iamnajib71/explainids
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=7860

RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 app
WORKDIR /app

RUN curl -sSfL "$REPO/archive/refs/tags/$REF.tar.gz" | tar xz --strip-components=1
RUN pip install -r requirements-deploy.txt && pip install --no-deps .

COPY SHA256SUMS ./models/SHA256SUMS
RUN cd models && for f in detector.joblib model_card.json replay.parquet; do \
      curl -sSfL -o "$f" "$REPO/releases/download/$REF/$f"; done \
    && sha256sum -c SHA256SUMS && chown -R app /app

USER app
EXPOSE 7860
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]
