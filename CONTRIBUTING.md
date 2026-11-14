# Contributing to AI-Driven WAF & Analytics Dashboard

Thank you for contributing! Please adhere to the following workflow and guidelines to ensure code quality and consistency across our team.

---

## 1. Branch Naming Conventions

All branches must follow this naming structure:
- `feat/<area>-<short-description>` (e.g., `feat/gateway-proxy-skeleton`, `feat/ml-normalizer`)
- `fix/<area>-<short-description>` (e.g., `fix/dashboard-chart-tooltip`)
- `docs/<short-description>` (e.g., `docs/update-architecture`)
- `test/<area>-<short-description>` (e.g., `test/normalizer-edge-cases`)

Areas correspond to project subdirectories: `gateway`, `ml`, `dashboard`, `demo`, `eval`, `docs`.

---

## 2. Commit Message Guidelines

We enforce **Conventional Commits**:
`<type>(<scope>): <short description>`

### Types
- `feat`: A new feature or capability
- `fix`: A bug fix
- `test`: Adding or updating test suites
- `docs`: Documentation updates
- `refactor`: Code refactoring without behavioral changes
- `chore`: Build tasks, package updates, housekeeping

### Examples
- `feat(gateway): implement pass-through proxy with streaming response`
- `feat(ml): add iterative URL and entity decoding normalizer`
- `fix(dashboard): escape payload text to prevent dashboard XSS`
- `test(gateway): verify masking of sensitive headers and parameters`

---

## 3. Pull Request Checklist

Before submitting a PR or merging your work, ensure:
1. **Tests Pass:** All unit/integration tests run and pass cleanly (`make test`).
2. **Linting & Formatting:** Code adheres to PEP 8 / TypeScript standards (`make lint`).
3. **No Hard-coded Secrets:** No API keys, passwords, or local IP overrides hardcoded.
4. **Docs Updated:** Update relevant documentation if interfaces or configurations changed.
5. **CRITICAL — Update PROGRESS.md:** Every PR or stage delivery **must** update `docs/PROGRESS.md` with:
   - Checkboxes ticked for completed deliverables.
   - Status transitions updated.
   - Any architectural/technical choices recorded in the Decisions Log.

---

## 4. Code Standards

- **Python**: Type hints required; black/ruff formatting; tests in `pytest`.
- **TypeScript**: Strict mode enabled; no implicit `any`; all logged content rendered safely (escaped text only, never raw HTML).
- **Safety**: Payloads are restricted strictly to textbook examples executed exclusively against local containers.
