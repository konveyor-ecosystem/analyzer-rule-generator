# Contributing to Analyzer Rule Generator

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code Quality Standards

This project enforces code quality standards through automated tooling:

- **Black** for code formatting (100 char line length)
- **isort** for import sorting
- **flake8** for linting
- **pytest** for testing with 80%+ coverage required

## Setting Up Your Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/konveyor-ecosystem/analyzer-rule-generator.git
   cd analyzer-rule-generator
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install black isort flake8 pre-commit
   ```

4. **Install pre-commit hooks (RECOMMENDED):**
   ```bash
   pre-commit install
   ```

   This will automatically run code quality checks before each commit.

## Making Changes

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

Follow these guidelines:

- Write clear, concise commit messages
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass
- Follow PEP 8 style guidelines

### 3. Run Code Quality Checks

**Before committing**, run these checks:

```bash
# Format code
black src/ scripts/ tests/
isort src/ scripts/ tests/

# Check for style violations
flake8 src/ scripts/ tests/

# Run tests
pytest
```

If you installed pre-commit hooks, these checks run automatically on `git commit`.

### 4. Commit Your Changes

Use DCO (Developer Certificate of Origin) signoff:

```bash
git commit -s -m "Your commit message"
```

The `-s` flag adds a "Signed-off-by" line, certifying that you have the right to submit the code under the project's license.

### 5. Push and Create a Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Pull Request Requirements

All pull requests must:

1. ✅ Pass all automated CI checks (code quality + tests)
2. ✅ Include tests for new functionality
3. ✅ Maintain or improve code coverage (80%+ required)
4. ✅ Include DCO signoff (`git commit -s`)
5. ✅ Have a clear description of changes

## Code Quality CI Checks

GitHub Actions automatically runs these checks on every PR:

- **Black** formatting check
- **isort** import sorting check
- **flake8** linting (max 150 violations allowed)
- **pytest** tests across Python 3.9, 3.10, 3.11, 3.12
- **Coverage** report (uploaded to Codecov)

If any check fails, the PR cannot be merged until fixed.

## Running Pre-commit Hooks Manually

To run all pre-commit hooks on all files:

```bash
pre-commit run --all-files
```

To skip pre-commit hooks (not recommended):

```bash
git commit --no-verify
```

## Testing

### Run All Tests

```bash
pytest
```

### Run Tests with Coverage

```bash
pytest --cov=src/rule_generator --cov-report=html
```

Then open `htmlcov/index.html` in your browser.

### Run Specific Tests

```bash
pytest tests/unit/test_generator.py
pytest tests/integration/test_cli.py::TestCLIBasicUsage
```

## Documentation

- Add docstrings to all public functions/classes
- Use Google-style docstrings
- Include examples in docstrings where helpful
- Update README.md if adding new features

## Questions?

Feel free to:

- Open an issue for discussion
- Ask questions in pull request comments
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
