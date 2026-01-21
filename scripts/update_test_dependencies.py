#!/usr/bin/env python3
"""
Update go-konveyor-tests dependency expectations from analyzer output.

This script:
1. Reads analyzer output (YAML/JSON) containing discovered dependencies
2. Generates Go code for the Dependencies section
3. Can update existing test case files or generate new ones

Usage:
    python scripts/update_test_dependencies.py \
        --analyzer-output /path/to/output/output.yaml \
        --test-case tc_myapp_deps.go

Kantra Output Location:
    After running: kantra analyze --input myapp --output analysis_output

    The dependencies are typically in one of these files:
    - analysis_output/output.yaml (main analysis results)
    - analysis_output/dependencies.yaml (if separate)

    Look for YAML with structure like:
      dependencies:
        - name: "org.springframework.boot:spring-boot-starter-web"
          version: "2.7.0"
          labels:
            - "konveyor.io/dep-source=java"

Example analyzer output formats supported:

    Format 1 (Konveyor standard):
      dependencies:
        - name: "org.springframework.boot:spring-boot-starter-web"
          version: "2.7.0"
          labels:
            - "konveyor.io/dep-source=java"

    Format 2 (Simple):
      dependencies:
        - name: "org.springframework.boot"
          version: "2.5.0"
          provider: "java"
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List

import yaml


class Incident:
    """Represents an incident (single occurrence of a rule violation)."""

    def __init__(self, file: str, line: int, message: str = ""):
        self.file = file
        self.line = line
        self.message = message

    def to_go_struct(self) -> str:
        """Convert to Go api.Incident struct."""
        return '''{{
\t\t\t\t\tFile: "{self.file}",
\t\t\t\t\tLine: {self.line},
\t\t\t\t}}'''


class Insight:
    """Represents an analysis insight (rule violation with incidents)."""

    def __init__(
        self,
        category: str,
        description: str,
        effort: int,
        ruleset: str,
        rule: str,
        incidents: List['Incident'],
    ):
        self.category = category
        self.description = description
        self.effort = effort
        self.ruleset = ruleset
        self.rule = rule
        self.incidents = incidents

    def to_go_struct(self) -> str:
        """Convert to Go api.Insight struct."""
        incidents_str = ""
        if self.incidents:
            incidents_str = "{\n"
            for inc in self.incidents:
                incidents_str += "\t\t\t\t" + inc.to_go_struct() + ",\n"
            incidents_str += "\t\t\t}"
        else:
            incidents_str = "{}"

        # Escape double quotes in description
        desc_escaped = self.description.replace('"', '\\"').replace('\n', ' ')

        return '''{{
\t\t\tCategory:    "{self.category}",
\t\t\tDescription: "{desc_escaped}",
\t\t\tEffort:      {self.effort},
\t\t\tRuleSet:     "{self.ruleset}",
\t\t\tRule:        "{self.rule}",
\t\t\tIncidents:   []api.Incident{incidents_str},
\t\t}}'''


class Tag:
    """Represents an analysis tag."""

    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category

    def to_go_struct(self) -> str:
        """Convert to Go api.Tag struct."""
        return '''{{
\t\t\tName:     "{self.name}",
\t\t\tCategory: api.Ref{{Name: "{self.category}"}},
\t\t}}'''


class Dependency:
    """Represents a technology dependency."""

    def __init__(self, name: str, version: str, provider: str):
        self.name = name
        self.version = version
        self.provider = provider

    def to_go_struct(self) -> str:
        """Convert to Go api.TechDependency struct."""
        return '''{{
\t\t\t\tName:     "{self.name}",
\t\t\t\tVersion:  "{self.version}",
\t\t\t\tProvider: "{self.provider}",
\t\t\t}}'''


def parse_analyzer_output(file_path: Path) -> List[Dependency]:
    """
    Parse analyzer output file and extract dependencies.

    Supports both YAML and JSON formats.

    Args:
        file_path: Path to analyzer output file

    Returns:
        List of Dependency objects
    """
    with open(file_path, 'r') as f:
        content = f.read()

    # Try YAML first, then JSON
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            print(f"Error: Could not parse {file_path} as YAML or JSON", file=sys.stderr)
            sys.exit(1)

    dependencies = []

    # Handle different output formats
    if isinstance(data, dict):
        # Format 1: {dependencies: [...]}
        if 'dependencies' in data:
            deps_data = data['dependencies']
        # Format 2: {techDependencies: [...]}
        elif 'techDependencies' in data:
            deps_data = data['techDependencies']
        # Format 3: Top-level keys are dependency names
        else:
            print(
                "Warning: Unrecognized format, attempting to extract dependencies", file=sys.stderr
            )
            deps_data = []
    elif isinstance(data, list):
        # Format 4: Kantra dependencies.yaml format - list of file objects
        # Each object has: {fileURI: ..., provider: ..., dependencies: [...]}
        # We need to extract all dependencies from all files
        deps_data = []
        for file_obj in data:
            if isinstance(file_obj, dict) and 'dependencies' in file_obj:
                file_provider = file_obj.get('provider', 'java')
                for dep in file_obj['dependencies']:
                    # Add file-level provider if not set on dependency
                    if isinstance(dep, dict) and 'provider' not in dep:
                        dep['provider'] = file_provider
                    deps_data.append(dep)

        # If we didn't find any nested dependencies, treat as direct list
        if not deps_data:
            deps_data = data
    else:
        print("Error: Unexpected data format", file=sys.stderr)
        sys.exit(1)

    # Parse dependency objects
    for dep in deps_data:
        if isinstance(dep, dict):
            name = dep.get('name') or dep.get('Name', '')
            version = dep.get('version') or dep.get('Version', '')
            provider = dep.get('provider') or dep.get('Provider')

            # If provider not explicitly set, try to extract from labels
            if not provider:
                labels = dep.get('labels', [])
                for label in labels:
                    if 'dep-source=' in label:
                        provider = label.split('dep-source=')[1]
                        break

            # Default to java if still not found
            if not provider:
                provider = 'java'

            if name:  # Only add if we have a name
                dependencies.append(Dependency(name, version, provider))

    return dependencies


def normalize_incident_path(file_path: str, target_prefix: str) -> str:
    """
    Normalize an incident file path by finding the project structure
    and replacing the local prefix with the target prefix.

    Args:
        file_path: Original file path from analysis
        target_prefix: Target prefix (e.g., "/shared/source/sample")

    Returns:
        Normalized file path
    """
    # Try to find a project module directory pattern
    # Look for directories that match patterns like: projectname-module-name
    # e.g., daytrader-ee7-web, daytrader-ee7-ejb, myapp-web, myapp-ejb
    parts = file_path.split('/')
    project_root_idx = -1

    for i, part in enumerate(parts):
        # Look for patterns with hyphens that indicate project modules
        # Must start with a letter and contain hyphens (typical Maven/Gradle project structure)
        if '-' in part and (
            part.endswith('-web')
            or part.endswith('-ejb')
            or part.endswith('-ear')
            or part.endswith('-war')
            or '-ee7-' in part
            or '-ee8-' in part
            or '-ee9-' in part
        ):
            project_root_idx = i
            break

    if project_root_idx > 0:
        # Found project module, rebuild path from this point
        relative_parts = parts[project_root_idx:]
        return target_prefix.rstrip('/') + '/' + '/'.join(relative_parts)

    # Fallback: Look for pom.xml or src directory
    for i, part in enumerate(parts):
        if part == 'pom.xml':
            # Check if this is a root pom.xml (no module before it)
            # Look back to see if there's a module directory
            has_module = False
            for j in range(i - 1, -1, -1):
                prev_part = parts[j]
                if '-' in prev_part and (
                    prev_part.endswith('-web')
                    or prev_part.endswith('-ejb')
                    or prev_part.endswith('-ear')
                    or '-ee' in prev_part
                ):
                    has_module = True
                    break

            if not has_module and i > 0:
                # Root pom.xml - just use the filename
                return target_prefix.rstrip('/') + '/' + part
            elif i > 0:
                # Module pom.xml - include the module directory
                relative_parts = parts[i - 1 :]
                return target_prefix.rstrip('/') + '/' + '/'.join(relative_parts)

        if part == 'src' and i > 0:
            # Go back one level to get the module directory
            relative_parts = parts[i - 1 :]
            return target_prefix.rstrip('/') + '/' + '/'.join(relative_parts)

    # Last resort: just prepend target prefix to basename
    return target_prefix.rstrip('/') + '/' + file_path.split('/')[-1]


def parse_violations(
    file_path: Path, normalize_path: str = None
) -> tuple[List[Insight], int, List[Tag]]:
    """
    Parse output.yaml file and extract violations/insights, effort, and tags.

    Args:
        file_path: Path to output.yaml file

    Returns:
        Tuple of (insights, total_effort, tags)
    """
    with open(file_path, 'r') as f:
        content = f.read()

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        print(f"Error: Could not parse {file_path} as YAML", file=sys.stderr)
        sys.exit(1)

    insights = []
    total_effort = 0
    tags_dict = {}  # Use dict to deduplicate tags

    # data is a list of rulesets
    if not isinstance(data, list):
        print("Error: Expected output.yaml to contain a list of rulesets", file=sys.stderr)
        sys.exit(1)

    for ruleset in data:
        ruleset_name = ruleset.get('name', '')

        # Handle technology-usage ruleset differently
        if ruleset_name == 'technology-usage':
            # Extract tags from technology-usage ruleset
            tech_tags = ruleset.get('tags', [])
            for tag_str in tech_tags:
                # Tags are in format "Category=Name" or just "Name"
                # Only include tags with categories (Hub filters out tags without categories)
                if '=' in tag_str:
                    category, name = tag_str.split('=', 1)
                    # Use "Category=Name" as key to deduplicate
                    tags_dict[tag_str] = Tag(name, category)
            continue  # Skip processing violations for this ruleset

        violations = ruleset.get('violations', {})

        for rule_id, violation in violations.items():
            category = violation.get('category', 'potential')
            description = violation.get('description', '')
            effort = violation.get('effort', 0)

            # Parse incidents
            incidents = []
            for inc_data in violation.get('incidents', []):
                uri = inc_data.get('uri', '')
                line_number = inc_data.get('lineNumber', 0)
                message = inc_data.get('message', '')

                # Extract file path from URI
                file_path_str = uri
                if uri.startswith('file://'):
                    file_path_str = uri[7:]  # Remove file:// prefix

                # Normalize path if requested
                if normalize_path:
                    file_path_str = normalize_incident_path(file_path_str, normalize_path)

                incidents.append(Incident(file_path_str, line_number, message))

            # Create insight
            if incidents:  # Only add if there are incidents
                insight = Insight(
                    category=category,
                    description=description,
                    effort=effort,
                    ruleset=ruleset_name,
                    rule=rule_id,
                    incidents=incidents,
                )
                insights.append(insight)
                total_effort += effort * len(incidents)  # Multiply effort by incident count

    # Convert tags dict to list
    tags = list(tags_dict.values())

    return insights, total_effort, tags


def generate_go_dependencies(dependencies: List[Dependency]) -> str:
    """
    Generate Go code for Dependencies field.

    Args:
        dependencies: List of Dependency objects

    Returns:
        Go code string
    """
    if not dependencies:
        return "\t\tDependencies: []api.TechDependency{},\n"

    deps_code = "\t\tDependencies: []api.TechDependency{\n"

    for dep in sorted(dependencies, key=lambda d: d.name):
        deps_code += "\t\t\t" + dep.to_go_struct() + ",\n"

    deps_code += "\t\t},\n"

    return deps_code


def generate_go_insights(insights: List[Insight]) -> str:
    """
    Generate Go code for Insights field.

    Args:
        insights: List of Insight objects

    Returns:
        Go code string
    """
    if not insights:
        return "\t\tInsights: []api.Insight{},\n"

    insights_code = "\t\tInsights: []api.Insight{\n"

    # Sort by ruleset then rule for consistency
    for insight in sorted(insights, key=lambda i: (i.ruleset, i.rule)):
        insights_code += "\t\t" + insight.to_go_struct() + ",\n"

    insights_code += "\t\t},\n"

    return insights_code


def generate_go_tags(tags: List[Tag]) -> str:
    """
    Generate Go code for AnalysisTags field.

    Args:
        tags: List of Tag objects

    Returns:
        Go code string
    """
    if not tags:
        return "\tAnalysisTags: []api.Tag{},\n"

    tags_code = "\tAnalysisTags: []api.Tag{\n"

    for tag in sorted(tags, key=lambda t: (t.name, t.category)):
        tags_code += "\t\t" + tag.to_go_struct() + ",\n"

    tags_code += "\t},\n"

    return tags_code


def update_test_case_file(
    file_path: Path,
    insights: List[Insight],
    effort: int,
    dependencies: List[Dependency],
    tags: List[Tag],
) -> None:
    """
    Update existing test case file with new analysis results.

    Args:
        file_path: Path to test case .go file
        insights: List of insights to update
        effort: Total effort score
        dependencies: List of dependencies to update
        tags: List of tags to update
    """
    if not file_path.exists():
        print(f"Error: Test case file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, 'r') as f:
        content = f.read()

    # Generate all sections (without the field names, since we'll preserve them from the original)
    # We need just the content between { and }, not the full "Insights: []api.Insight{...},"
    insights_full = generate_go_insights(insights)
    deps_full = generate_go_dependencies(dependencies)
    tags_full = generate_go_tags(tags)

    # Extract just the inner content (everything after the opening brace)
    # For Insights: "\t\tInsights: []api.Insight{\n" ... "\t\t},\n" -> just the middle part
    insights_code = '\n'.join(insights_full.split('\n')[1:-2])  # Skip first line and last two lines
    deps_code = '\n'.join(deps_full.split('\n')[1:-2])
    tags_code = '\n'.join(tags_full.split('\n')[1:-2])

    # Update Analysis-level Effort field (not insight-level Effort)
    # Must match Effort that comes after "Analysis: api.Analysis{" and before "Insights:"
    effort_pattern = r'(Analysis:\s+api\.Analysis\{\s*\n\s+)Effort:\s+\d+,'
    if re.search(effort_pattern, content):
        # Update existing Analysis-level Effort
        content = re.sub(effort_pattern, rf'\1Effort: {effort},', content, count=1)
    else:
        # Add Effort before Insights (or after Analysis{ if no Insights)
        content = re.sub(r'(Analysis:\s+api\.Analysis\{)', rf'\1\n\t\tEffort: {effort},', content)

    # Update Insights section
    # Match from "Insights: []api.Insight{" to the closing "}," at the same indentation level
    # Use non-greedy match and require the closing brace to be followed by Dependencies/AnalysisTags
    insights_pattern = r'(Insights:\s+\[]api\.Insight\s*\{).*?(\n\t\t\},\n)(?=\t\tDependencies:)'
    if re.search(insights_pattern, content, re.DOTALL):
        print("  → Updating existing Insights section")
        content = re.sub(
            insights_pattern,
            r'\1\n' + insights_code + r'\n\t\t},\n',
            content,
            count=1,  # Only replace the first occurrence
            flags=re.DOTALL,
        )
    else:
        print("  → Adding new Insights section")
        # Add Insights after Analysis-level Effort (not Insight-level Effort)
        content = re.sub(
            r'(Analysis:\s+api\.Analysis\{\s*\n\s*Effort:\s+\d+,)',
            rf'\1\n{insights_code}',
            content,
            count=1,  # Only replace the first occurrence
        )

    # Update Dependencies section
    deps_pattern = r'(Dependencies:\s+\[]api\.TechDependency\s*\{).*?(\n\t\t\},\n)(?=\t\})'
    if re.search(deps_pattern, content, re.DOTALL):
        content = re.sub(
            deps_pattern,
            r'\1\n' + deps_code + r'\n\t\t},\n',
            content,
            count=1,  # Only replace the first occurrence
            flags=re.DOTALL,
        )

    # Update AnalysisTags section
    tags_pattern = r'(AnalysisTags:\s+\[]api\.Tag\s*\{).*?(\n\t\},\n)(?=\})'
    if re.search(tags_pattern, content, re.DOTALL):
        content = re.sub(
            tags_pattern,
            r'\1\n' + tags_code + r'\n\t},\n',
            content,
            count=1,  # Only replace the first occurrence
            flags=re.DOTALL,
        )
    else:
        # Add AnalysisTags after closing Analysis brace
        content = re.sub(r'(\s+\},\n)(\})', rf'\1{tags_code}\n\2', content)

    # Write back
    with open(file_path, 'w') as f:
        f.write(content)

    print(f"✓ Updated {file_path}")


def generate_test_case_template(
    test_name: str,
    app_name: str,
    dependencies: List[Dependency],
    insights: List[Insight] = None,
    effort: int = 0,
    tags: List[Tag] = None,
) -> str:
    """
    Generate a complete test case file template.

    Args:
        test_name: Name of the test case
        app_name: Application name
        dependencies: List of dependencies
        insights: List of insights (violations)
        effort: Total effort score
        tags: List of analysis tags

    Returns:
        Complete Go file content
    """
    # Generate all sections
    effort_line = f"\t\tEffort: {effort},\n" if effort > 0 else ""
    insights_code = generate_go_insights(insights or []).rstrip()
    deps_code = generate_go_dependencies(dependencies).rstrip()
    tags_code = generate_go_tags(tags or []).rstrip()

    # Sanitize names for Go variable naming
    var_name = re.sub(r'[^a-zA-Z0 - 9]', '', test_name.title())

    template = '''package analysis

import (
\t"github.com/konveyor/go-konveyor-tests/data"
\t"github.com/konveyor/go-konveyor-tests/hack/addon"
\t"github.com/konveyor/tackle2-hub/api"
)

var {var_name} = TC{{
\tName: "{test_name}",
\tApplication: data.{app_name},
\tTask: Analyze,
\tWithDeps: true,
\tLabels: addon.Labels{{
\t\tIncluded: []string{{
\t\t\t"konveyor.io/target=cloud-readiness",
\t\t}},
\t}},
\tAnalysis: api.Analysis{{
{effort_line}{insights_code}
{deps_code}
\t}},
{tags_code}
}}
'''

    return template


def main():
    parser = argparse.ArgumentParser(
        description="Update go-konveyor-tests dependencies from analyzer output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update existing test case file:
  python scripts/update_test_dependencies.py \\
      --analysis-dir /path/to/analysis-output \\
      --test-case tc_myapp_deps.go

  # Generate new test case file:
  python scripts/update_test_dependencies.py \\
      --analysis-dir /path/to/analysis-output \\
      --output tc_newapp_deps.go \\
      --test-name "NewApp Analysis" \\
      --app-name "NewApp"
        """,
    )

    parser.add_argument(
        '--analysis-dir',
        required=True,
        help=(
            'Path to Kantra analysis output directory '
            '(contains dependencies.yaml and output.yaml)'
        ),
    )

    parser.add_argument(
        '--normalize-path',
        help=(
            'Normalize incident file paths by replacing local prefix with this value '
            '(e.g., "/shared/source/sample")'
        ),
    )

    parser.add_argument('--test-case', help='Path to existing test case file to update')

    parser.add_argument('--output', help='Path for new test case file (if creating new)')

    parser.add_argument('--test-name', help='Test case name (required for new files)')

    parser.add_argument('--app-name', help='Application name (required for new files)')

    parser.add_argument(
        '--print-only', action='store_true', help='Print generated code without writing files'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.test_case and not args.output:
        print("Error: Either --test-case or --output must be specified", file=sys.stderr)
        sys.exit(1)

    if args.output and (not args.test_name or not args.app_name):
        print(
            "Error: --test-name and --app-name are required when creating new file", file=sys.stderr
        )
        sys.exit(1)

    # Find analysis files in directory
    analysis_dir = Path(args.analysis_dir)
    dependencies_file = analysis_dir / 'dependencies.yaml'
    output_file = analysis_dir / 'output.yaml'

    if not dependencies_file.exists():
        print(f"Error: Could not find dependencies.yaml in {analysis_dir}", file=sys.stderr)
        sys.exit(1)

    if not output_file.exists():
        print(f"Error: Could not find output.yaml in {analysis_dir}", file=sys.stderr)
        sys.exit(1)

    # Parse dependencies
    print(f"Parsing dependencies: {dependencies_file}")
    dependencies = parse_analyzer_output(dependencies_file)
    print(f"  ✓ Found {len(dependencies)} dependencies")

    # Parse violations
    print(f"Parsing violations: {output_file}")
    insights, effort, tags = parse_violations(output_file, args.normalize_path)
    print(f"  ✓ Found {len(insights)} insights (total effort: {effort})")
    print(f"  ✓ Found {len(tags)} tags")
    if args.normalize_path:
        print(f"  ✓ Normalized paths to: {args.normalize_path}")

    # Generate code
    if args.test_case:
        # Update existing file with all sections
        if args.print_only:
            print("\nWould update test case with:")
            print(f"  - Effort: {effort}")
            print(f"  - {len(insights)} insights")
            print(f"  - {len(dependencies)} dependencies")
            print(f"  - {len(tags)} tags")
        else:
            update_test_case_file(Path(args.test_case), insights, effort, dependencies, tags)

    else:
        # Generate new file
        content = generate_test_case_template(
            args.test_name, args.app_name, dependencies, insights, effort, tags
        )

        if args.print_only:
            print("\nGenerated test case file:")
            print(content)
        else:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(content)
            print(f"✓ Generated {output_path}")


if __name__ == '__main__':
    main()
