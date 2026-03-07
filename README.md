# PromptFuzz

**The open source adversarial security testing framework for LLM applications.**

[![Tests](https://github.com/your-org/promptfuzz/actions/workflows/tests.yml/badge.svg)](https://github.com/your-org/promptfuzz/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

You ship an LLM-powered product. You add a system prompt. You think it's secure.
It isn't. **PromptFuzz finds out before your users do.**

PromptFuzz fires 165+ real adversarial attack prompts — jailbreaks, prompt injections, data extraction attempts, goal hijacking, and edge cases — at your application and generates a professional vulnerability report in seconds.

---

## Features

- **165+ real attacks** across 5 categories — no generic placeholders
- **Async concurrent execution** — test at speed with configurable workers
- **Three target modes** — Python callable, HTTP endpoint, or YAML config
- **Rich terminal output** — colour-coded severity table with score gauge
- **HTML report** — dark-theme dashboard with expandable vulnerability cards
- **JSON export** — machine-readable output for CI/CD pipelines
- **CI/CD integration** — `--fail-on critical` exits with code 1 on findings
- **Zero LLM dependency** — works on any function or HTTP endpoint

---

## Quick Start

```bash
pip install promptfuzz
```

### Test a Python function

```python
from promptfuzz import Fuzzer

def chat(message: str) -> str:
    return f"Hello! I'm a helpful assistant. {message}"

fuzzer = Fuzzer(target=chat, context="demo chatbot", categories=["jailbreak"])
result = fuzzer.run()
result.report()
result.save("report.html")
```

### Test an HTTP endpoint

```bash
promptfuzz scan --target https://your-api.com/chat --context "support bot"
```

### Use a config file

```bash
promptfuzz scan --config promptfuzz.yaml --output report.html --fail-on high
```

---

## Attack Categories

| Category | Count | Description |
|---|---|---|
| `jailbreak` | 40 | DAN variants, persona switches, roleplay bypasses, encoding tricks |
| `injection` | 40 | Classic overrides, delimiter attacks, template injection, indirect injection |
| `data_extraction` | 30 | System prompt leakage, credential extraction, reflection attacks |
| `goal_hijacking` | 25 | Competitor promotion, purpose replacement, loyalty switches |
| `edge_case` | 30 | Empty input, Unicode attacks, SQL/XSS injection strings, encoding edge cases |

```bash
promptfuzz list-attacks
```

---

## CLI Reference

```
promptfuzz scan [OPTIONS]

  --target, -t       URL or module:function path
  --config, -c       YAML config file (mutually exclusive with --target)
  --context          Description of the target application
  --categories, -C   Attack categories to run (repeatable)
  --output, -o       Save HTML report to path
  --json             Save JSON report to path
  --severity, -s     Minimum severity to display [low|medium|high|critical]
  --fail-on, -f      Exit code 1 if vulns at/above this severity found
  --max-workers, -w  Concurrent request workers (default: 5)
  --timeout, -T      Per-attack timeout seconds (default: 30)
  --verbose, -v      Enable verbose output
```

---

## Config File

```yaml
target: "https://api.example.com/chat"
context: "customer support bot"
categories:
  - jailbreak
  - injection
max_workers: 5
timeout: 30
headers:
  Authorization: "Bearer YOUR_TOKEN"
input_field: message
output_field: response
```

---

## CI/CD Integration

```yaml
- name: Security scan
  run: |
    pip install promptfuzz
    promptfuzz scan \
      --target https://staging-api.example.com/chat \
      --categories jailbreak injection \
      --output report.html \
      --fail-on high
  continue-on-error: false
```

---

## Security Score

| Score | Risk Level |
|---|---|
| 80–100 | Low Risk |
| 50–79 | Medium Risk |
| 20–49 | High Risk |
| 0–19 | Critical Risk |

Score formula: `max(0, 100 - (critical×25 + high×10 + medium×5 + low×2))`

---

## Roadmap

- [ ] Semantic similarity detection strategy
- [ ] Multi-turn attack sequences
- [ ] Claude / Gemini / Mistral SDK integrations
- [ ] Custom attack JSON support
- [ ] Slack/GitHub PR comment reporter
- [ ] Attack success rate benchmarks

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `ruff check .` and `pytest tests/ -v`
5. Open a pull request

---

## License

AGPL-3.0 © PromptFuzz Contributors
