# Shadow Hunter — hackathon submission kit

**Track:** Security — Attack & Defend
**Tagline:** Autonomous intelligence. Deterministic security.
**Baseline tested:** 89d1b61, 24 November 2026

## Reproduce the local demonstration

From the repository root, use Python 3.11+ and an isolated virtual environment.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[server,dev]"
.\.venv\Scripts\python.exe scripts/run_red_blue_synthetic.py --rounds 8 --output demo-evidence.json
.\.venv\Scripts\python.exe -m pytest -q tests/test_synthetic_eval_api.py tests/test_sponsors.py tests/test_band_worker.py tests/test_sponsor_preflight.py
.\.venv\Scripts\python.exe -m shadow_hunter.sponsor_preflight
```

The evaluation is deterministic, local and synthetic; it uses no customer records, payment providers or hosted models. For the operator console follow the root README's local development setup. Never expose demo credentials or a local-mode server to the public Internet.

## Verified evidence

- Eight of eight expected synthetic outcomes passed.
- Seven of seven unsafe synthetic actions were blocked, and the one legitimate control passed.
- Zero false denials and zero executed refunds.
- 36 focused API and sponsor-boundary tests passed.
- BAND and Lyzr were not configured in the tested environment.
- No hosted inference or remote agent communication was verified in this run.

## Submission assets

- [Devpost description](devpost.md)
- [Architecture](architecture.md)
- [Synthetic evidence](synthetic-evidence.json)
- [Demo storyboard](../adal-demo-script.md)
- [Sponsor integration instructions](../sponsor-integrations.md)

## Remaining release checklist

Configure and verify an authorized BAND/Lyzr exchange with synthetic inputs only; capture genuine console screenshots and a demo recording; upload the recording; confirm team details and exact Devpost requirements. No production or public deployment is claimed. The source package is reproducible locally; there is no verified public binary or hosted demo.
