# Detection — Tycoon2FA (Week 3)

Detection content written by the group from the processed dataset, and tested.

| File | Description |
|---|---|
| `tycoon2fa.yar` | 2 YARA rules: landing-page artifacts, invisible-Unicode JavaScript |
| `make_test_samples.py` | Generates the **synthetic, harmless** test corpus (`sample_*`) |
| `sample_pos_*` | Files that imitate the kit's patterns: they must match |
| `sample_neg_*` | Benign look-alikes: they must NOT match (false-positive check) |
| `yara_test_results.txt` | Output of YARA 4.5.2 on the corpus (6/6 passed) |
| `tycoon2fa_axios_signin.yml` | Sigma rule: successful Entra ID sign-in with an `axios/` User-Agent |
| `sample_signin_logs.jsonl` | 8 synthetic sign-in events (Sentinel `SigninLogs` fields) |
| `hunt_signin_logs.py` | Applies the Sigma rule and IOC matching (`../dataset/tycoon2fa_iocs.csv`) to the logs |
| `hunt_results.txt` | Hunt output |

Reproduce:

```bash
python3 detection/make_test_samples.py
for f in detection/sample_*; do yara detection/tycoon2fa.yar "$f"; done
pip install pyyaml && python3 detection/hunt_signin_logs.py
```

The test samples contain no real phishing code. The "hidden" payload is the string `console.log('synthetic test')`, and all hosts use the reserved `.invalid` TLD.
