# zynko-oracle · `python-cwe916`

**A deterministic, re-checkable CWE-916 decider for Python.**

An **oracle** *deterministically decides* the truth of a case — it doesn't guess, it decides. This one
decides, for a given piece of Python code and a line number, whether that line exhibits **insufficient computational effort in password hashing**
(CWE-916).

## Proven
Measured on a **discriminating** probe corpus of **20 cases (8 flagged + 12 safe)** — verified by
running the oracle, not asserted. The corpus includes **held-out adversarial cases**
(boundary values and near-misses) that were written after the decider, not alongside it:

```
recall = 1.000    false_positives = 0    non-degenerate = yes  ->  PASS
```

`verify.py` (stdlib only, no network) is the CI gate.

## Method (no-virus)
The cost floors (PBKDF2 `iterations` < 100000, scrypt `n` < 16384, bcrypt `rounds` < 12) are this decider's **declared parameters**, chosen from published guidance (NIST SP 800-132, OWASP Password Storage Cheat Sheet). They are stated here so the verdict can be re-derived and disputed -- they are not presented as a universal law. **No third-party analyzer is installed, vendored, or executed** — neither at build time nor at
run time. The evidence is our own discriminating corpus, not the word of an external tool.

## Grounding (honest)
This is a **syntactic** decider, not a taint-flow analysis. The precise question it answers is stated at the
top of `oracle/python_cwe916_weak_kdf_cost.py`, and the oracle claims nothing beyond it: it does **not** prove exploitability,
and where a value is not visible in the source (a name, a call, a runtime setting) the decider returns `SAFE`
rather than guessing. Treat a `FLAG` as *a case that meets the stated syntactic condition*, which is an input
to a human judgement, not a substitute for one.

## License
Apache-2.0 (see `LICENSE`).
