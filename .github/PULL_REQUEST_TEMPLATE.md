## Summary

What does this PR change, and why? Link the issue it resolves, if any.

## Type of change

- [ ] Bug fix
- [ ] New detector / detection improvement
- [ ] Documentation
- [ ] Chore / dev tooling / CI
- [ ] Other (describe):

## Corpus-impact checklist

This project treats `tests/data/golden_corpus.jsonl` (54 cases) as a frozen,
schema-validated behavioural contract (`CONTRIBUTING.md`, PLAN.md §16).

- [ ] **This PR does not touch any corpus case's expected verdict,
      transformation, or reason codes**, and `python scripts/validate_contracts.py`
      still reports all 54 cases passing unchanged.

      — OR, if it does —

- [ ] **This PR changes the expected outcome of one or more corpus cases.**
      List which case IDs, and why the change is correct rather than a
      regression:

      - Case ID(s):
      - Why the new expected outcome is correct:
      - ADR documenting this change: `docs/adr/00__-____.md` (a corpus
        change without an accompanying ADR will not be merged — see
        `CONTRIBUTING.md`'s "never touch the frozen corpus without an ADR"
        rule)

## Checks run locally

- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `mypy app` (strict)
- [ ] `pytest --cov=app` — all tests pass, coverage gate met
- [ ] `python scripts/validate_contracts.py`
- [ ] New behaviour has a new or updated test — this project does not
      accept untested changes to `app/`

## Anything else the reviewer should know?

Trade-offs, things you're unsure about, follow-up work you're deliberately
not doing here.
