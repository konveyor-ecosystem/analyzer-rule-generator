#!/usr/bin/env python3
"""
Display rule statistics in a formatted table for analysis and demos.

This script analyzes Konveyor analyzer rule files and generates summary
statistics grouped by various attributes (category, effort, complexity, etc.).
Useful for:
- Understanding rule distribution and coverage
- Identifying complexity patterns
- Generating metrics for documentation
- Creating demo data for presentations

Features:
    - Groups rules by category, effort, or custom attributes
    - Displays results in a formatted table
    - Supports glob patterns for analyzing multiple files
    - Calculates totals and percentages

Usage:
    # Analyze all rules matching a pattern
    python scripts/show_rule_stats.py "examples/output/spring-boot-*.yaml"

    # Analyze rules in a directory
    python scripts/show_rule_stats.py "examples/output/patternfly-v6/*.yaml"

    # Show effort distribution
    python scripts/show_rule_stats.py "rules/*.yaml" --attribute effort

Example Output:
    Rule Statistics for: spring-boot-3-to-spring-boot-4-*.yaml

    Total rules: 42

    By Category:
    mandatory:  28 (67%)
    potential:  14 (33%)

    By Effort:
    1 (TRIVIAL):  12 (29%)
    3 (LOW):      18 (43%)
    5 (MEDIUM):   10 (24%)
    7 (HIGH):      2 (5%)

Arguments:
    pattern: Glob pattern matching rule YAML files (required)
    --attribute: Attribute to group by (default: category)
                 Options: category, effort, migration_complexity, labels

Note:
    The script expects YAML files containing arrays of analyzer rules.
    Each rule should have the attributes being analyzed.
"""

import sys
from collections import defaultdict
from glob import glob
from pathlib import Path

import yaml


def count_rules_by_attribute(file_path, attribute):
    """Count rules grouped by an attribute."""
    with open(file_path) as f:
        rules = yaml.safe_load(f)

    counts = defaultdict(int)
    for rule in rules:
        value = rule.get(attribute, 'unknown')
        if isinstance(value, list):
            value = ', '.join(value)
        counts[str(value)] = counts.get(str(value), 0) + 1

    return counts


def print_table(headers, rows, title=None):
    """Print a simple ASCII table."""
    if title:
        print(f"\n╔{'═' * (len(title) + 2)}╗")
        print(f"║ {title} ║")
        print(f"╚{'═' * (len(title) + 2)}╝\n")

    # Calculate column widths
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Print header
    header_line = (
        "│ " + " │ ".join(str(h).ljust(col_widths[i]) for i, h in enumerate(headers)) + " │"
    )
    separator = "├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
    top = "┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
    bottom = "└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"

    print(top)
    print(header_line)
    print(separator)

    # Print rows
    for row in rows:
        cells = " │ ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
        print(f"│ {cells} │")

    print(bottom)


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/show_rule_stats.py <pattern>")
        sys.exit(1)

    pattern = sys.argv[1]
    files = sorted(glob(pattern))

    if not files:
        print(f"No files matching pattern: {pattern}")
        sys.exit(1)

    # File summary table
    file_rows = []
    total_rules = 0

    for file_path in files:
        with open(file_path) as f:
            rules = yaml.safe_load(f)

        rule_count = len(rules)
        total_rules += rule_count

        concern = Path(file_path).stem.split('-')[-1]
        size = Path(file_path).stat().st_size / 1024  # KB

        file_rows.append([concern.title(), rule_count, f"{size:.1f} KB"])

    print_table(["Concern", "Rules", "Size"], file_rows, title="📋 Generated Files")

    # Aggregate statistics across all files
    all_categories = defaultdict(int)
    all_efforts = defaultdict(int)

    for file_path in files:
        categories = count_rules_by_attribute(file_path, 'category')
        efforts = count_rules_by_attribute(file_path, 'effort')

        for cat, count in categories.items():
            all_categories[cat] += count
        for eff, count in efforts.items():
            all_efforts[eff] += count

    # Category breakdown
    cat_rows = [[cat.title(), count, "█" * count] for cat, count in sorted(all_categories.items())]
    print_table(["Category", "Count", "Distribution"], cat_rows, title="📊 Rule Categories")

    # Effort breakdown
    eff_rows = [[f"Effort {eff}", count, "▓" * count] for eff, count in sorted(all_efforts.items())]
    print_table(["Effort Level", "Count", "Distribution"], eff_rows, title="⚡ Effort Distribution")

    # Summary
    print(f"\n✅ Total: {total_rules} rules across {len(files)} file(s)\n")


if __name__ == "__main__":
    main()
