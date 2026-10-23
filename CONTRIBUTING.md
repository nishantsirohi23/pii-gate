# Contributing

Thank you for helping. A few rules keep this project trustworthy.

## Never commit real data

No real names, numbers, addresses or keys, not in code, tests, docs, issues or screenshots. Test values
are generated in `tests/_synthetic.py`, which computes valid check digits from arbitrary digits. If you
need a new kind of identifier, add a generator there. CI runs `pii-gate scan .` on the repository.

## Adding a detector

1. Put the pattern in `src/pii_gate/detectors.py` (or `exfil.py` / `sqlgate.py`).
2. Register the rule name and its default level in `src/pii_gate/config.py`.
3. Add tests: it fires on the synthetic value, it stays silent on a near miss (bad checksum, wrong
   length, documentation placeholder), the masked sample never contains the value.
4. Document the rule in the README table.

Default levels: `block` only when false positives are rare (a checksum or a fixed token format).
Heuristic patterns default to `warn`.

## Running the tests

```
pip install -e .
python -m unittest discover -s tests -v
pii-gate scan .
```

Python 3.9 is the floor; keep the code free of third-party dependencies.

## Reporting a bypass

If you find a way for an agent to get personal data past the gate, please report it privately as
described in `SECURITY.md` instead of opening a public issue.
