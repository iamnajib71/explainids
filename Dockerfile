# ExplainIDS: API + web console in one small image. Runs the same on a laptop, a VM or a free
# Hugging Face Space.
#   docker build -t explainids .
#   docker run -p 8000:8000 explainids            -> http://localhost:8000
# Trained artefacts (models/detector.joblib, model_card.json, replay.parquet) are copied in when
# present; without them the app starts in synthetic demo mode.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=8000
# LightGBM needs the OpenMP runtime
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*

# Non-root user (uid 1000 is also what Hugging Face Spaces expects)
RUN useradd -m -u 1000 app
WORKDIR /app

COPY requirements-deploy.txt pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install -r requirements-deploy.txt && pip install --no-deps .

COPY --chown=app api ./api
COPY --chown=app web ./web
COPY --chown=app models ./models

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health')"
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]
