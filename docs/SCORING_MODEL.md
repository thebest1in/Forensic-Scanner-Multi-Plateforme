# Risk scoring model

The composite score is bounded to 0–100 and combines YARA, heuristics, tool
results, IOC/network intelligence, entropy/browser signals, and correlation.
Authoritative YARA findings receive their rule weight; contextual findings are
dampened and cannot independently escalate a verdict. Exact coefficients and
caps are implemented in `analyzer.py`; each release must record the ruleset
commit and score specification version in the canonical report.

Verdict bands currently used by the engine are `CLEAN`, `LOW_RISK`,
`SUSPICIOUS`, and `CRITICAL`. A result with unavailable optional tools must
retain limitations rather than convert missing coverage into a negative result.
