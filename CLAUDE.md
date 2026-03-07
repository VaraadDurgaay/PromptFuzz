# CLAUDE.md

# PromptFuzz — Claude Code Instructions

## What This Project Is
PromptFuzz is an open source Python security testing framework 
that automatically finds vulnerabilities in LLM applications.
It fires adversarial attack prompts and generates vulnerability 
reports. Target audience: AI developers. Goal: become the #1 
open source AI security tool on GitHub.

## Build Order (Always Follow This)
1. pyproject.toml + skeleton
2. attacks/*.json (real attacks, no placeholders)
3. attacks/loader.py
4. analyzer.py
5. runner.py
6. fuzzer.py
7. reporter.py
8. cli.py
9. examples/
10. tests/
11. README.md
12. .github/workflows/

## Code Rules — Never Break These
- NEVER use `requests` — always use `httpx`
- NEVER use `argparse` — always use `click`
- NEVER use `setup.py` — only `pyproject.toml`
- NEVER leave placeholder comments like "# TODO: implement this"
- NEVER write a function without a docstring and type hints
- NEVER hardcode strings — use constants
- ALWAYS handle exceptions with helpful `rich` error messages
- ALWAYS write async functions with a sync wrapper

## Tech Stack (Strict)
- CLI: click
- HTTP: httpx  
- Terminal UI: rich
- HTML templates: jinja2
- Config: pyyaml
- Testing: pytest + pytest-asyncio
- Linting: ruff
- Python: 3.10+ only

## Code Style
- Type hints on EVERY function
- Docstring on EVERY function and class
- Max line length: 88 chars (black default)
- Use dataclasses for data objects, not dicts
- Prefer explicit over clever
- Code must read like a textbook — clear, clean, obvious

## Attack JSON Rules
- Every attack must be real and unique — no generic placeholders
- Every attack needs: id, name, category, severity, description,
  prompt, detection, tags, remediation
- Minimum counts: jailbreaks(40), injections(40), 
  data_extraction(30), goal_hijacking(25), edge_cases(30)
- Prompts must be varied — not the same attack reworded

## What "Done" Means For Any Feature
- Works end to end
- Has error handling
- Has a test in /tests
- Follows code style rules above
- No ruff errors

## File Structure — Do Not Deviate
promptfuzz/
├── promptfuzz/
│   ├── __init__.py
│   ├── fuzzer.py
│   ├── runner.py
│   ├── analyzer.py
│   ├── reporter.py
│   ├── cli.py
│   └── attacks/
│       ├── __init__.py
│       ├── loader.py
│       ├── jailbreaks.json
│       ├── injections.json
│       ├── data_extraction.json
│       ├── goal_hijacking.json
│       └── edge_cases.json
├── tests/
├── examples/
├── pyproject.toml
├── README.md
├── LICENSE
└── .github/workflows/

## When Stuck or Uncertain
- Always prefer the simpler solution
- If two approaches exist, pick the one with fewer dependencies
- Ask before making structural changes to the project
- Never silently skip a requirement from the MVP prompt

## Git Commit Style
- feat: new feature
- fix: bug fix
- docs: documentation
- test: adding tests
- refactor: code cleanup
- chore: config/tooling
Example: "feat: add keyword detection strategy to analyzer"

## Current Status
- [ ] Project not started yet
- Start from Step 1 of build order