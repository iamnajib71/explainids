# models/

Trained artefacts are generated, not committed (see `.gitignore`):

```bash
python scripts/build_processed.py data/raw/cicids2017 data/processed/cicids2017.parquet
python scripts/train_baseline.py data/processed/cicids2017.parquet --models lgbm,xgb,rf --results docs/results/cicids2017_baseline.md
```

This writes `detector.joblib` (selected model), `model_card.json` (metrics shown in the Model lab) and
`replay.parquet` (held-out real flows streamed by the Live monitor). Without them the app runs in synthetic demo mode.
