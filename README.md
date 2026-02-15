# Analyzer Rule Generator

[![Tests](https://github.com/konveyor-ecosystem/analyzer-rule-generator/workflows/Tests/badge.svg)](https://github.com/konveyor-ecosystem/analyzer-rule-generator/actions)
[![codecov](https://codecov.io/gh/konveyor-ecosystem/analyzer-rule-generator/branch/main/graph/badge.svg)](https://codecov.io/gh/konveyor-ecosystem/analyzer-rule-generator)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/github/license/konveyor-ecosystem/analyzer-rule-generator)](LICENSE)

AI-powered tool for generating [Konveyor analyzer](https://github.com/konveyor/analyzer-lsp) rules from migration guides and documentation.

## Overview

The Analyzer Rule Generator uses Large Language Models (LLMs) to automatically extract migration patterns from documentation and generate static analysis rules for the Konveyor analyzer. This helps migration teams quickly create comprehensive rulesets without manual authoring.

## Features

- **Multiple Input Formats**: URLs, Markdown files, plain text, ESLint codemods
- **Multi-Language Support**: Java, TypeScript/React, Go, Python, CSS, and more
- **LLM-Powered Extraction**: Automatically identifies migration patterns, complexity, and conditions
- **ESLint Rule Extraction**: Direct extraction from ESLint codemod repositories (e.g., PatternFly pf-codemods) without LLM
- **Migration Complexity Classification**: Automatic classification (trivial, low, medium, high, expert) for generated and existing rules
- **Konveyor Analyzer Format**: Generates rules compatible with analyzer-lsp
- **Flexible LLM Support**: OpenAI, Anthropic Claude, Google Gemini
- **Smart Provider Detection**: Automatically uses Java or Builtin provider based on detected language
- **Pattern Detection**: Extracts fully qualified class names, regex patterns, and file globs
- **Rule Validation**: Syntactic and optional semantic validation to ensure rule quality
- **Test Data Generation**: AI-powered generation of test applications for rule validation
- **CI Test Updater**: Automated updates to go-konveyor-tests expectations

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set up your LLM API key
export OPENAI_API_KEY="your-key-here"

# Generate rules from a migration guide
python scripts/generate_rules.py \
  --guide https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide \
  --source spring-boot-3 \
  --target spring-boot-4 \
  --output examples/output/spring-boot-4.0/migration-rules.yaml
```

## Claude Code Skill

**Interactive AI Assistant for Rule Generation**

This project includes a [Claude Code](https://claude.com/claude-code) skill that provides an interactive AI assistant for generating migration rules. Instead of running command-line scripts manually, you can have a natural conversation with Claude to generate rules.

### Using the Skill

```
konveyor-rules
```

The skill will guide you through:
1. Providing the migration guide (URL or file)
2. Specifying source and target frameworks
3. Choosing LLM provider and options
4. Reviewing generated rules and next steps

### Benefits

- **Natural language interface** - Describe what you need in plain English
- **Interactive guidance** - Claude asks clarifying questions and provides suggestions
- **Automatic validation** - Checks inputs and provides helpful error messages
- **Context-aware** - Understands the project structure and suggests best practices

See [.claude/skills/konveyor-rules/README.md](.claude/skills/konveyor-rules/README.md) for complete documentation.

## How It Works

```mermaid
flowchart TD
    A[📄 Migration Guide] --> B[🤖 Generate Rules]
    B --> C[📋 Konveyor Rules]
    C -.Optional.-> C1[✅ Validate Rules]
    C1 --> C
    C --> D[🤖 Generate Test Data]
    D --> E[🧪 Kantra Test]

    E -->|Pass| F[📦 Submit to konveyor/rulesets]
    E -->|Fail| D

    F --> G[🔬 Run Analysis]
    G --> H[🔄 Update CI Tests]
    H --> I[📦 Submit to go-konveyor-tests]

    F -.Link PRs.-> I

    style A fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style B fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style C fill:#fff9c4,stroke:#f9a825,stroke-width:2px
    style C1 fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,stroke-dasharray: 5 5
    style D fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style E fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style F fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style G fill:#ffebee,stroke:#c62828,stroke-width:2px
    style H fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style I fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
```

**Complete Workflow:**

1. **Generate Rules**: LLM extracts migration patterns from documentation
   - Detects language (Java vs TypeScript/React/Go/Python)
   - For Java: Fully qualified class names and location types
   - For others: Regex patterns and file globs
2. **Validate Rules** (Optional): Check rule quality before testing
   - Syntactic validation: Required fields, effort scores, pattern checks
   - Semantic validation: AI-powered description/pattern alignment
3. **Generate Test Data**: AI creates test applications with violations
4. **Test Locally**: Validate rules with Kantra
5. **Submit Rules**: PR to konveyor/rulesets
6. **Run Analysis**: Test rules on reference applications
7. **Update CI Tests**: Automated update of go-konveyor-tests expectations
8. **Submit Tests**: PR to go-konveyor-tests (linked with rules PR)

## Examples

### Java Migration (Spring Boot 3 to 4)

```bash
python scripts/generate_rules.py \
  --guide https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide \
  --source spring-boot-3 \
  --target spring-boot-4 \
  --output examples/output/spring-boot-4.0/migration-rules.yaml
```

### TypeScript/React Migration (PatternFly v5 to v6)

**Option 1: From ESLint Codemods (Recommended - No LLM required)**

```bash
python scripts/generate_rules.py \
  --eslint-repo https://github.com/patternfly/pf-codemods.git \
  --source patternfly-v5 \
  --target patternfly-v6 \
  --output examples/output/patternfly-v6/
```

Extracts rules directly from PatternFly's official ESLint codemods. **Advantages:**
- No LLM API costs
- High-quality rules based on official codemods
- Includes code examples and documentation links
- Supports simple renames, removals, and deprecations (~20-25 rules extracted)

**Option 2: From Migration Guide (LLM-based)**

```bash
python scripts/generate_rules.py \
  --guide https://www.patternfly.org/get-started/upgrade/ \
  --source patternfly-v5 \
  --target patternfly-v6 \
  --follow-links \
  --max-depth 1 \
  --output examples/output/patternfly-v6/migration-rules.yaml
```

Generates **41 comprehensive rules** with hybrid detection (nodejs + builtin providers) for eliminating false positives.

## Example Output

### Java Provider Rules

```yaml
- ruleID: spring-boot-3-to-spring-boot-4-00001
  description: Replace deprecated Spring Boot 3 annotations
  effort: 3
  category: mandatory
  labels:
    - konveyor.io/source=spring-boot-3
    - konveyor.io/target=spring-boot-4
  when:
    java.referenced:
      pattern: org.springframework.web.bind.annotation.RestController
      location: ANNOTATION
  message: "Review Spring Boot 4.0 migration requirements for REST controllers"
  links:
    - url: "https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide"
      title: "Spring Boot 4.0 Migration Guide"
  migration_complexity: low
```

### Builtin Provider Rules (TypeScript/React/Go/Python)

```yaml
- ruleID: patternfly-v5-to-patternfly-v6-00001
  description: isDisabled should be replaced with isAriaDisabled
  effort: 3
  category: potential
  labels:
    - konveyor.io/source=patternfly-v5
    - konveyor.io/target=patternfly-v6
  when:
    builtin.filecontent:
      pattern: isDisabled\s*[=:]
      filePattern: '*.{tsx,jsx,ts,js}'
  message: "The isDisabled prop has been renamed to isAriaDisabled for better accessibility"
```

## Migration Complexity Classification

The tool automatically classifies migration complexity for generated rules and provides a script to classify existing rulesets.

### Complexity Levels

- **trivial** (95%+ AI success): Namespace changes, mechanical fixes (e.g., javax → jakarta)
- **low** (80%+ AI success): Simple API equivalents, straightforward replacements
- **medium** (60%+ AI success): Requires context understanding, moderate refactoring
- **high** (30-50% AI success): Architectural changes, complex migrations
- **expert** (<30% AI success): Custom implementations, likely needs human review

### Classifying Existing Rulesets

Add complexity classifications to existing Konveyor analyzer rulesets:

```bash
# Preview classifications (dry run)
python scripts/classify_existing_rules.py \
  --ruleset examples/output/spring-boot/migration-rules.yaml \
  --dry-run

# Apply classifications
python scripts/classify_existing_rules.py \
  --ruleset examples/output/spring-boot/migration-rules.yaml

# Batch process multiple rulesets
bash scripts/batch_classify_rulesets.sh /path/to/rulesets
```

The classifier analyzes:
- Pattern descriptions and messages
- Rule effort scores
- When condition complexity
- Migration keywords and indicators

See [docs/guides/migration-complexity.md](docs/guides/migration-complexity.md) for complete documentation.

## Rule Viewer

**🌐 [View Rules Online](https://konveyor-ecosystem.github.io/analyzer-rule-generator/rule-viewer.html)** - Interactive web viewer for any Konveyor ruleset

Load and explore rules from:
- GitHub URLs (paste any rule file URL)
- Local YAML files (drag & drop)
- Share with `?url=` parameter

See [Rule Viewers Guide](docs/reference/rule-viewers.md) for more options.

## Documentation

**Getting Started:**
- [Rule Viewers Guide](docs/reference/rule-viewers.md) - View and explore generated rules

**Guides:**
- [Konveyor Submission Guide](docs/guides/konveyor-submission-guide.md) - Complete end-to-end submission workflow
- [Updating CI Tests](docs/guides/updating-ci-tests.md) - Step-by-step guide for go-konveyor-tests
- [Testing Guide](docs/guides/testing.md) - Testing generated rules
- [Complete Automation Guide](docs/guides/complete-automation.md) - Full automation workflow

**Technical Reference:**
- [Generate Rules Script Reference](docs/reference/generate-rules.md) - Complete script documentation
- [Validate Rules Script Reference](docs/reference/validate-rules.md) - Rule validation documentation
- [CI Test Updater Reference](docs/reference/ci-test-updater.md) - Script documentation
- [Java Rule Schema](docs/reference/java-rule-schema.md) - Rule structure and syntax

## Integration with Konveyor

Generated rules and tests integrate with:
- [Konveyor Analyzer](https://github.com/konveyor/analyzer-lsp) - Static analysis engine
- [Konveyor Rulesets](https://github.com/konveyor/rulesets) - Official rule repository
- [go-konveyor-tests](https://github.com/konveyor/go-konveyor-tests) - CI test expectations

## Requirements

- Python 3.9+
- LLM API access (OpenAI, Anthropic, or Google)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Code Quality Standards

This project enforces code quality through automated tooling:

- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **pytest** for testing (80%+ coverage required)

### Quick Setup for Contributors

```bash
# Install dev dependencies
pip install black isort flake8 pre-commit

# Install pre-commit hooks (runs checks automatically)
pre-commit install

# Run checks manually
black src/ scripts/ tests/
isort src/ scripts/ tests/
flake8 src/ scripts/ tests/
pytest
```

All pull requests are automatically checked by GitHub Actions for code quality and test coverage.

## License

Apache License 2.0

## Related Projects

- [konveyor/analyzer-lsp](https://github.com/konveyor/analyzer-lsp) - Static analysis engine
- [konveyor/rulesets](https://github.com/konveyor/rulesets) - Official rulesets
- [konveyor-iq](https://github.com/tsanders-rh/konveyor-iq) - LLM evaluation framework
