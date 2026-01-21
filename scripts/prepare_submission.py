#!/usr/bin/env python3
"""
Prepare Konveyor ruleset submission package.

This script helps prepare generated rules for submission to the Konveyor rulesets
repository by creating the required directory structure and test templates.
"""

import argparse
import shutil
import sys
from pathlib import Path

import yaml

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rule_generator.security import is_safe_path


def create_test_template(rule_file: Path, output_dir: Path, data_dir_name: str) -> Path:
    """
    Create a test template file for the given rule file.

    Args:
        rule_file: Path to the rule YAML file
        output_dir: Directory to write test file to
        data_dir_name: Name of the test data directory

    Returns:
        Path to created test file
    """
    # Read rules to extract rule IDs
    with open(rule_file, 'r') as f:
        content = yaml.safe_load(f)
        # Handle both list format and multi-document format
        if isinstance(content, list):
            rules = content
        else:
            rules = [content]

    rule_ids = [rule['ruleID'] for rule in rules if isinstance(rule, dict) and 'ruleID' in rule]

    # Create test structure
    test_content = {
        'rulesPath': f'../{rule_file.name}',
        'providers': [{'name': 'java', 'dataPath': f'data/{data_dir_name}'}],
        'tests': [],
    }

    # Add test case for each rule
    for rule_id in rule_ids:
        test_content['tests'].append(
            {
                'ruleID': rule_id,
                'testCases': [
                    {
                        'name': 'tc - 1',
                        'analysisParams': {'mode': 'source-only'},
                        'hasIncidents': {'atLeast': 1},
                    }
                ],
            }
        )

    # Write test file
    test_file_name = rule_file.stem + '.test.yaml'
    test_file_path = output_dir / test_file_name

    with open(test_file_path, 'w') as f:
        yaml.dump(test_content, f, default_flow_style=False, sort_keys=False)

    return test_file_path


def create_test_data_structure(
    output_dir: Path, data_dir_name: str, source: str, version: str
) -> Path:
    """
    Create skeleton test data directory structure.

    Args:
        output_dir: Directory to create test data in
        data_dir_name: Name of the test data directory
        source: Source technology (e.g., 'spring-boot')
        version: Source version (e.g., '3.5')

    Returns:
        Path to created test data directory
    """
    test_data_dir = output_dir / data_dir_name
    test_data_dir.mkdir(parents=True, exist_ok=True)

    # Create source directory structure
    src_dir = test_data_dir / 'src' / 'main' / 'java' / 'com' / 'example'
    src_dir.mkdir(parents=True, exist_ok=True)

    # Create minimal pom.xml
    pom_content = """<?xml version="1.0" encoding="UTF - 8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven - 4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>{data_dir_name}-test</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <packaging>jar</packaging>

    <properties>
        <java.version>17</java.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
    </properties>

    <dependencies>
        <!-- TODO: Add dependencies for {source} {version} -->
    </dependencies>
</project>
"""

    pom_path = test_data_dir / 'pom.xml'
    with open(pom_path, 'w') as f:
        f.write(pom_content)

    # Create placeholder Java file
    java_content = """package com.example;

/**
 * Test application for {source} migration rules.
 *
 * TODO: Add code that uses deprecated/removed APIs that should trigger rules.
 * Each rule should have at least one violation in this test code.
 */
public class Application {{
    public static void main(String[] args) {{
        // TODO: Add test code here
    }}
}}
"""

    java_path = src_dir / 'Application.java'
    with open(java_path, 'w') as f:
        f.write(java_content)

    return test_data_dir


def create_readme(
    output_dir: Path, rule_file: Path, source: str, target: str, guide_url: str
) -> Path:
    """
    Create README for the submission package.

    Args:
        output_dir: Directory to write README to
        rule_file: Path to the rule file
        source: Source technology/version
        target: Target technology/version
        guide_url: URL to migration guide

    Returns:
        Path to created README
    """
    readme_content = """# {source} to {target} Migration Rules

## Overview

This package contains analyzer rules for migrating from {source} to {target}.

Generated from: {guide_url}

## Files

- `{rule_file.name}` - Migration rules
- `tests/{rule_file.stem}.test.yaml` - Test definitions
- `tests/data/` - Test application code

## Testing

Run tests locally:

```bash
kantra test tests/{rule_file.stem}.test.yaml
```

## Installation

Copy files to Konveyor rulesets repository:

```bash
# Determine target directory (e.g., spring-boot, openjdk21, etc.)
TARGET_DIR=/path/to/rulesets/default/generated/YOUR_TECHNOLOGY

# Copy rules
cp {rule_file.name} $TARGET_DIR/

# Copy tests
cp -r tests/* $TARGET_DIR/tests/

# Run tests
cd $TARGET_DIR
kantra test tests/{rule_file.stem}.test.yaml
```

## Next Steps

1. **Complete test data**
   - Edit `tests/data/*/pom.xml` to add dependencies
   - Edit `tests/data/*/src/main/java/com/example/Application.java`
     with code that uses deprecated APIs
   - Ensure each rule has at least one violation in test code

2. **Run tests locally**
   - Install Kantra: https://github.com/konveyor/kantra
   - Run: `kantra test tests/{rule_file.stem}.test.yaml`
   - Verify all tests pass

3. **Submit to Konveyor**
   - Fork https://github.com/konveyor/rulesets
   - Create feature branch
   - Copy files to appropriate directory
   - Create PR with test results

See `docs/konveyor-submission-guide.md` for detailed instructions.
"""

    readme_path = output_dir / 'README.md'
    with open(readme_path, 'w') as f:
        f.write(readme_content)

    return readme_path


def main():
    parser = argparse.ArgumentParser(
        description='Prepare Konveyor ruleset submission package',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Prepare Spring Boot 4.0 rules for submission
  python scripts/prepare_submission.py \\
    --rules examples/output/spring-boot - 4.0/migration-rules.yaml \\
    --source spring-boot - 3.5 \\
    --target spring-boot - 4.0 \\
    --guide-url \\
      https://github.com/spring-projects/spring-boot/wiki/Spring-Boot - 4.0-Migration-Guide \\
    --output submission/spring-boot - 4.0
        """,
    )

    parser.add_argument('--rules', required=True, help='Path to generated rule YAML file')
    parser.add_argument(
        '--source', required=True, help='Source technology/version (e.g., spring-boot - 3.5)'
    )
    parser.add_argument(
        '--target', required=True, help='Target technology/version (e.g., spring-boot - 4.0)'
    )
    parser.add_argument('--guide-url', required=True, help='URL to migration guide')
    parser.add_argument('--output', required=True, help='Output directory for submission package')
    parser.add_argument(
        '--data-dir-name',
        help='Name for test data directory (default: extracted from rule file name)',
    )

    args = parser.parse_args()

    # Validate paths for security (check for path traversal attacks)
    if not is_safe_path(args.rules):
        print(f"Error: Rules path '{args.rules}' contains suspicious patterns", file=sys.stderr)
        return 1
    if not is_safe_path(args.output):
        print(f"Error: Output path '{args.output}' contains suspicious patterns", file=sys.stderr)
        return 1

    # Validate inputs
    rule_file = Path(args.rules)
    if not rule_file.exists():
        print(f"Error: Rule file not found: {rule_file}", file=sys.stderr)
        return 1

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine test data directory name
    data_dir_name = args.data_dir_name
    if not data_dir_name:
        # Extract from rule file name (e.g., spring-boot - 3.5-to - 4.0-mongodb.yaml -> mongodb)
        parts = rule_file.stem.split('-')
        # Try to find a meaningful suffix after version numbers
        data_dir_name = '-'.join(parts[-2:]) if len(parts) > 2 else 'test'

    print(f"Preparing Konveyor submission package: {args.source} → {args.target}")
    print(f"Output directory: {output_dir}")
    print()

    # Copy rule file
    print("[1/4] Copying rule file...")
    rule_dest = output_dir / rule_file.name
    shutil.copy2(rule_file, rule_dest)
    print(f"  ✓ {rule_dest}")

    # Create test directory structure
    test_dir = output_dir / 'tests'
    test_dir.mkdir(exist_ok=True)

    # Create test template
    print("[2/4] Creating test template...")
    test_file = create_test_template(rule_file, test_dir, data_dir_name)
    print(f"  ✓ {test_file}")

    # Create test data structure
    print("[3/4] Creating test data structure...")
    data_dir = test_dir / 'data'
    data_dir.mkdir(exist_ok=True)
    test_data_dir = create_test_data_structure(
        data_dir, data_dir_name, args.source, args.source.split('-')[-1]
    )
    print(f"  ✓ {test_data_dir}")
    print(f"  ✓ {test_data_dir / 'pom.xml'}")
    print(f"  ✓ {test_data_dir / 'src/main/java/com/example/Application.java'}")

    # Create README
    print("[4/4] Creating README...")
    readme_file = create_readme(output_dir, rule_file, args.source, args.target, args.guide_url)
    print(f"  ✓ {readme_file}")

    print()
    print("✓ Submission package ready!")
    print()
    print("Next steps:")
    print(f"  1. Complete test data in: {test_data_dir}")
    print("  2. Install Kantra: https://github.com/konveyor/kantra")
    print(f"  3. Run tests: kantra test {test_file}")
    print(f"  4. See {readme_file} for submission instructions")
    print()
    print("Package structure:")
    print(f"  {output_dir}/")
    print(f"  ├── {rule_file.name}")
    print("  ├── README.md")
    print("  └── tests/")
    print(f"      ├── {rule_file.stem}.test.yaml")
    print(f"      └── data/{data_dir_name}/")
    print("          ├── pom.xml")
    print("          └── src/main/java/...")

    return 0


if __name__ == '__main__':
    sys.exit(main())
