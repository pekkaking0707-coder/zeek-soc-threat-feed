# models.md — models & scoring functions (PLAN §12)

Fill as detectors land. Required per detector:

- Scoring function definition (thresholds / model) and its parameters
- Confidence mapping (how raw score -> 0..1) — PLAN §5 requires this documented
- Training data + split (DGA: DGArchive-style samples vs Tranco benign)
- Confusion matrix / precision-recall on the labeled evaluation PCAPs
- Severity base lookup reference: PLAN §5 table (do not restate values here)

## DGA n-gram scorer (placeholder)

- Model: char n-gram (3..5) log-likelihood vs Tranco-benign corpus
- Output: log-likelihood; confidence = calibrated mapping documented here
- Status: TODO

## Beaconing KS/CUSUM

- Parameters: window_n, iat_cv_max, min_samples (see detectors/beaconing.py)
- KS-test baseline + CUSUM change-point parameters: TODO

## JA4 reference lists

- Whitelist source (fleet baseline) + blacklist source (e.g. abuse.ch): TODO
