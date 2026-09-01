# zynko-oracle · `python-cwe916`

**A deterministic, re-checkable CWE-916 decider for Python.**

An **oracle** *deterministically decides* the truth of a case — it doesn't guess, it decides. This one
decides, for a given piece of Python code and a line number, whether that line exhibits **insufficient computational effort in password hashing**
(CWE-916).

## Proven
Measured on a **discriminating** probe corpus of **27 cases (12 flagged + 15 safe)** — verified by
running the oracle, not asserted. The corpus includes **held-out adversarial cases**
(boundary values and near-misses) that were written after the decider, not alongside it:

```
recall = 1.000    false_positives = 0    non-degenerate = yes  ->  PASS
```

These numbers hold **on the published probe set (N=27)**. A probe set is a floor, not a
coverage measure — see *Known limitations* below.

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

## Known limitations (measured, not guessed)
This decider was hardened after an independent adversarial review (10 divergences found across the first
wave, nine of them from a single root: deciding on the *call name* instead of the *import binding*). It now
resolves aliases, function references and `getattr` indirection, and excludes locally shadowed names.
What it still cannot see:

- **Dynamic construction.** A callable assembled at run time (`ops[key](x)`, a name rebound inside a
  branch, a value read from configuration) has no static binding, so the decider returns `SAFE`.
- **Cross-file flow.** Only the submitted source is parsed. A wrapper defined in another module is not
  followed.
- **Value provenance.** Where a value is not a literal or a module-level constant, the decider does not
  guess what it holds.

`SAFE` therefore means *"the stated syntactic condition was not established here"*, not *"this code is
secure"*. The corpus below is a floor on the decider's behaviour, not a measure of its coverage.

Those limitations are **concrete and re-checkable**, not a disclaimer: `probes/known_limitations.jsonl`
lists the exact forms this decider does not see, each with its current verdict and the reason. That file
is deliberately **not** part of the `verify.py` gate — labelling those cases `SAFE` in the gate corpus
would hide the gap instead of recording it. If a later version closes one of them, the change is visible
there.

## License
Apache-2.0 (see `LICENSE`).
