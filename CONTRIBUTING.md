# Contributing to Unified Ops Dashboard

Thank you for your interest in contributing to the Unified Ops Dashboard — a real-time, multi-server operations monitoring platform.

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- `pip install -r requirements.txt`
- Optional: Npcap (Windows) or root (Linux) for packet sniffing

### Running Locally
```bash
python main.py
```
Open `http://localhost:8081` in your browser.

### Running a Remote Agent
```bash
python agent.py
```

---

## 🌿 Branching Strategy

- `main` — stable release branch
- `develop` — active development
- Feature branches: `feature/<name>`
- Bug fixes: `fix/<description>`

---

## 📝 Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]
[optional footer]
```

**Types:**
- `feat` — new feature
- `fix` — bug fix
- `perf` — performance improvement
- `refactor` — code refactor
- `docs` — documentation
- `test` — adding/fixing tests
- `chore` — tooling, config, CI

**Examples:**
```
feat(dashboard): add toast notification system for alerts
fix(agent): handle malformed Authorization headers gracefully
perf(database): trigger flush on batch buffer overflow
docs(readme): update installation prerequisites
refactor(monitor): consolidate alert config getter/setter
```

---

## 🧪 Testing

Before submitting a pull request:

1. Ensure the dashboard starts without errors: `python main.py`
2. Verify the frontend loads at `http://localhost:8081`
3. Test Settings tab saves and reloads all three thresholds
4. Test dark mode toggle (all charts should update)
5. Test process kill via custom modal (no browser `confirm()`)
6. Verify log analysis returns valid JSON
7. Test keyboard shortcuts: `R` (refresh), `D` (dark mode), `1-9` (tabs)

---

## 🐛 Reporting Bugs

Please open an [Issue](../../issues) with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Python version, OS
- Relevant log output

---

## 💡 Feature Requests

Open an Issue tagged `enhancement`. Please include:
- Use case and motivation
- Proposed UI/API design (if applicable)

---

## 🔒 Security Issues

Please do **not** open a public issue for security vulnerabilities. Email the maintainer directly.

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the project's existing license.
