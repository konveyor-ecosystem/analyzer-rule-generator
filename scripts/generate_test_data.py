#!/usr/bin/env python3
"""
Generate test data (code with violations) for Konveyor analyzer rules.

This script uses an LLM to generate a minimal test application that
contains code violations matching the generated rules.

Supports multiple languages: Java, TypeScript, Go, Python, etc.
"""

import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from rule_generator.config import config
from rule_generator.llm import get_llm_provider
from rule_generator.security import is_safe_path, validate_framework_name

# Set up Jinja2 template environment for test generation
TEMPLATE_DIR = Path(__file__).parent.parent / 'templates' / 'test_generation'
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(),
    trim_blocks=True,
    lstrip_blocks=True,
)


def detect_language(rules: list) -> str:
    """
    Detect the programming language from rule conditions.

    Args:
        rules: List of rule dictionaries

    Returns:
        Language name (java, typescript, go, python, etc.)
    """
    # First, check labels for language hints (e.g., konveyor.io/source=go - 1.17)
    for rule in rules:
        labels = rule.get('labels', [])
        for label in labels:
            if isinstance(label, str):
                label_lower = label.lower()
                # Check source/target labels for language hints
                if 'go-' in label_lower or '=go' in label_lower or label_lower.startswith('go'):
                    return 'go'
                elif 'java-' in label_lower or '=java' in label_lower or 'spring' in label_lower:
                    return 'java'
                elif (
                    'node' in label_lower
                    or 'react' in label_lower
                    or 'angular' in label_lower
                    or 'typescript' in label_lower
                ):
                    return 'typescript'
                elif 'python' in label_lower or 'django' in label_lower:
                    return 'python'

    def check_condition(cond):
        """Helper to check a single condition."""
        if 'nodejs.referenced' in cond or 'nodejs.dependency' in cond:
            return 'typescript'
        elif 'java.referenced' in cond or 'java.dependency' in cond:
            return 'java'
        elif 'builtin.filecontent' in cond or 'builtin.file' in cond:
            # Check filePattern for language hints
            builtin_cond = cond.get('builtin.filecontent') or cond.get('builtin.file', {})
            file_pattern = builtin_cond.get('filePattern', '')

            # Check for JS/TS patterns: .js, .jsx, .ts, .tsx
            # Common patterns: \.(j|t)sx?$, \.tsx?$, \.jsx?$, etc.
            if any(
                pattern in file_pattern
                for pattern in ['.ts', '.tsx', '.js', '.jsx', '(j|t)s', 'jsx?', 'tsx?']
            ):
                return 'typescript'
            elif '.go' in file_pattern:
                return 'go'
            elif '.py' in file_pattern:
                return 'python'
            elif '.java' in file_pattern:
                return 'java'
        return None

    for rule in rules:
        when = rule.get('when', {})

        # Check for 'and' conditions
        if 'and' in when:
            and_conditions = when['and'] if isinstance(when['and'], list) else [when['and']]
            for cond in and_conditions:
                lang = check_condition(cond)
                if lang:
                    return lang
        # Check for 'or' conditions
        elif 'or' in when:
            or_conditions = when['or'] if isinstance(when['or'], list) else [when['or']]
            for cond in or_conditions:
                lang = check_condition(cond)
                if lang:
                    return lang
        # Check direct conditions
        else:
            lang = check_condition(when)
            if lang:
                return lang

    # Default to java if can't determine
    return 'java'


def get_language_config(language: str) -> dict:
    """
    Get language-specific configuration for test generation.

    Args:
        language: Programming language name

    Returns:
        Dict with language configuration
    """
    configs = {
        'java': {
            'build_file': 'pom.xml',
            'build_file_type': 'xml',
            'source_dir': 'src/main/java/com/example',
            'main_file': 'Application.java',
            'main_file_type': 'java',
            'package_manager': 'Maven',
            'test_instructions': 'Maven project with dependencies',
        },
        'typescript': {
            'build_file': 'package.json',
            'build_file_type': 'json',
            'source_dir': 'src',
            'main_file': 'App.tsx',
            'main_file_type': 'tsx',
            'package_manager': 'npm',
            'test_instructions': 'npm project with dependencies',
        },
        'go': {
            'build_file': 'go.mod',
            'build_file_type': 'go',
            'source_dir': '.',
            'main_file': 'main.go',
            'main_file_type': 'go',
            'package_manager': 'Go modules',
            'test_instructions': 'Go module with dependencies',
        },
        'python': {
            'build_file': 'requirements.txt',
            'build_file_type': 'text',
            'source_dir': 'src',
            'main_file': 'main.py',
            'main_file_type': 'python',
            'package_manager': 'pip',
            'test_instructions': 'Python project with requirements.txt',
        },
    }

    return configs.get(language, configs['java'])


def determine_filename_from_filepattern(rules: list, base_filename: str, language: str) -> str:
    """
    Determine appropriate filename based on filePattern requirements from rules.

    Args:
        rules: List of rule dictionaries
        base_filename: Base filename from lang_config (e.g., 'App.tsx')
        language: Programming language

    Returns:
        Appropriate filename that matches filePattern requirements
    """
    # Extract all filePatterns from rules
    file_patterns = []
    for rule in rules:
        when = rule.get('when', {})

        def extract_file_pattern(cond):
            """Extract filePattern from a condition."""
            if 'builtin.filecontent' in cond:
                return cond['builtin.filecontent'].get('filePattern', '')
            elif 'builtin.file' in cond:
                return cond['builtin.file'].get('filePattern', '')
            return ''

        # Check different condition structures
        if 'and' in when:
            and_conditions = when['and'] if isinstance(when['and'], list) else [when['and']]
            for cond in and_conditions:
                pattern = extract_file_pattern(cond)
                if pattern:
                    file_patterns.append(pattern)
        elif 'or' in when:
            or_conditions = when['or'] if isinstance(when['or'], list) else [when['or']]
            for cond in or_conditions:
                pattern = extract_file_pattern(cond)
                if pattern:
                    file_patterns.append(pattern)
        else:
            # Direct condition
            pattern = extract_file_pattern(when)
            if pattern:
                file_patterns.append(pattern)

    # If no filePatterns found, return base filename
    if not file_patterns:
        return base_filename

    # Use the first filePattern to determine the filename
    file_pattern = file_patterns[0]

    # Extract base name and extension from base_filename
    parts = base_filename.rsplit('.', 1)
    base_name = parts[0] if len(parts) == 2 else base_filename
    extension = parts[1] if len(parts) == 2 else ''

    # Check for test file patterns (common across languages)
    # Look for patterns like: .test. or .spec. in the filePattern
    # The filePattern is a regex, so it may contain escapes like \. for literal dots
    has_test = 'test' in file_pattern.lower()
    has_spec = 'spec' in file_pattern.lower()

    if has_test or has_spec:
        # Determine which pattern to use (prefer test over spec)
        pattern_type = 'test' if has_test else 'spec'

        # Determine the extension from the pattern
        if language == 'typescript':
            # Check if pattern allows tsx files
            # Look for tsx, (j|t)sx, or similar patterns
            if 'tsx' in file_pattern or '(j|t)sx' in file_pattern or '(ts|tsx)' in file_pattern:
                return f"{base_name}.{pattern_type}.tsx"
            else:
                return f"{base_name}.{pattern_type}.ts"
        elif language == 'java':
            # Java uses suffix style: AppTest.java
            return f"{base_name}Test.java"
        elif language == 'go':
            # Go uses suffix style: app_test.go
            return f"{base_name}_test.go"
        elif language == 'python':
            # Python uses prefix style: test_app.py
            return f"test_{base_name}.py"
        else:
            # Generic fallback
            if extension:
                return f"{base_name}.{pattern_type}.{extension}"
            return f"{base_name}.{pattern_type}"

    # If no special pattern detected, return base filename
    return base_filename


def extract_patterns_from_rules(rules: list, language: str) -> list:
    """
    Extract patterns that need to be tested from rules.

    Args:
        rules: List of rule dictionaries
        language: Programming language

    Returns:
        List of pattern dictionaries with code hints
    """
    patterns_to_test = []

    def process_condition(cond, rule_id, description, message=''):
        """Process a single condition and extract pattern info."""
        pattern_info = {
            'ruleID': rule_id,
            'description': description,
            'message': message,
            'pattern': None,
            'location': None,
            'provider': None,
            'component': None,
            'code_hint': None,
        }

        # Check for nodejs.referenced
        if 'nodejs.referenced' in cond:
            nodejs_ref = cond['nodejs.referenced']
            pattern_info['pattern'] = nodejs_ref.get('pattern')
            pattern_info['component'] = nodejs_ref.get('pattern')
            pattern_info['location'] = nodejs_ref.get('location', 'IMPORT')
            pattern_info['provider'] = 'nodejs'

            # Generate code hint for nodejs.referenced patterns
            code_hint = generate_code_hint_from_pattern(
                pattern_info['pattern'], language, description, message
            )
            if code_hint:
                pattern_info['code_hint'] = code_hint

        # Check for java provider
        elif 'java.referenced' in cond:
            java_ref = cond['java.referenced']
            pattern_info['pattern'] = java_ref.get('pattern')
            pattern_info['location'] = java_ref.get('location')
            pattern_info['provider'] = 'java'

            # Extract import statements if location is IMPORT
            if java_ref.get('location') == 'IMPORT' and message:
                imports = extract_java_imports_from_message(message)
                if imports:
                    pattern_info['code_hint'] = '\n'.join(imports)

        elif 'java.dependency' in cond:
            java_dep = cond['java.dependency']
            pattern_info['pattern'] = java_dep.get('name')
            pattern_info['location'] = 'DEPENDENCY'
            pattern_info['provider'] = 'java'

        # Check for builtin.filecontent (this contains the actual code pattern!)
        elif 'builtin.filecontent' in cond:
            builtin = cond['builtin.filecontent']
            pattern_info['pattern'] = builtin.get('pattern')
            pattern_info['location'] = 'FILE_CONTENT'
            pattern_info['provider'] = 'builtin'
            pattern_info['filePattern'] = builtin.get('filePattern', '')

            # Extract component name from import patterns
            # Pattern like: import.*\{{[^}}]*\\bComponentName\\b[^}}]*\}}.*from
            builtin_pattern = builtin.get('pattern', '')
            if builtin_pattern.startswith('import') and '\\b' in builtin_pattern:
                # Extract component name between \b markers in import pattern
                import re as pattern_re

                # Look for \bWordCharacters\b or \\bWordCharacters\\b (double-escaped) pattern
                # Handle both single and double backslashes
                component_match = pattern_re.search(r'\\+b([A-Z]\w+)\\+b', builtin_pattern)
                if component_match:
                    pattern_info['import_component'] = component_match.group(1)

            # Check if this is a configuration file pattern
            file_pattern = builtin.get('filePattern', '')
            if any(
                ext in file_pattern
                for ext in ['.properties', '.yaml', '.yml', '.factories', '.xml']
            ):
                pattern_info['is_config_file'] = True
                # Determine config file type and name
                if '.properties' in file_pattern and 'spring.factories' not in file_pattern:
                    pattern_info['config_type'] = 'properties'
                    pattern_info['config_file_name'] = 'application.properties'
                elif 'spring.factories' in file_pattern or '.factories' in file_pattern:
                    pattern_info['config_type'] = (
                        'properties'  # spring.factories uses properties format
                    )
                    pattern_info['config_file_name'] = 'spring.factories'
                    pattern_info['config_file_path'] = (
                        'META-INF/spring.factories'  # Standard location
                    )
                elif '.yaml' in file_pattern or '.yml' in file_pattern:
                    pattern_info['config_type'] = 'yaml'
                    pattern_info['config_file_name'] = 'application.yaml'
                elif '.xml' in file_pattern:
                    pattern_info['config_type'] = 'xml'
                    pattern_info['config_file_name'] = 'application.xml'
                else:
                    pattern_info['config_type'] = 'properties'  # default
                    pattern_info['config_file_name'] = 'application.properties'
            else:
                pattern_info['is_config_file'] = False

            # Parse JSX/TSX patterns to generate code hints
            jsx_pattern = builtin.get('pattern', '')
            # Debug: Print what we're about to call
            import os

            if os.environ.get('DEBUG_CODE_HINTS'):
                print("  DEBUG: Calling generate_code_hint_from_pattern")
                print(f"    Pattern: {repr(jsx_pattern)}")
                print(f"    Language: {language}")
            pattern_info['code_hint'] = generate_code_hint_from_pattern(
                jsx_pattern, language, description, message
            )
            if os.environ.get('DEBUG_CODE_HINTS'):
                print(f"    Result: {repr(pattern_info['code_hint'])}")

        elif 'builtin.file' in cond:
            builtin = cond['builtin.file']
            pattern_info['pattern'] = builtin.get('pattern')
            pattern_info['location'] = 'FILE_PATTERN'
            pattern_info['provider'] = 'builtin'
            pattern_info['filePattern'] = builtin.get('filePattern', '')

        return pattern_info if pattern_info['pattern'] else None

    for rule in rules:
        rule_id = rule.get('ruleID')
        description = rule.get('description', '')
        message = rule.get('message', '')
        when = rule.get('when', {})

        patterns = []

        # Handle 'and' conditions
        if 'and' in when:
            and_conditions = when['and'] if isinstance(when['and'], list) else [when['and']]
            for cond in and_conditions:
                info = process_condition(cond, rule_id, description, message)
                if info:
                    patterns.append(info)

        # Handle 'or' conditions
        elif 'or' in when:
            or_conditions = when['or'] if isinstance(when['or'], list) else [when['or']]
            for cond in or_conditions:
                info = process_condition(cond, rule_id, description, message)
                if info:
                    patterns.append(info)

        # Handle direct condition
        else:
            info = process_condition(when, rule_id, description, message)
            if info:
                patterns.append(info)

        # Merge patterns for the same rule
        if patterns:
            merged = {
                'ruleID': rule_id,
                'description': description,
                'message': message,
                'patterns': patterns,
                'component': None,
                'code_hint': None,
            }

            # Extract component name and code hint
            for p in patterns:
                if p.get('component'):
                    merged['component'] = p['component']
                if p.get('code_hint'):
                    merged['code_hint'] = p['code_hint']

            patterns_to_test.append(merged)

    return patterns_to_test


def extract_java_imports_from_message(message: str) -> list:
    """
    Extract Java import statements from a rule message's "Before:" section.

    Args:
        message: Rule message (may contain Before/After code examples)

    Returns:
        List of import statement strings
    """
    if not message:
        return []

    imports = []

    # Look for code blocks after "Before:"
    # Handle both actual newlines and literal \n (backslash-n) in the message
    before_match = re.search(
        r'Before:(?:\\n|\n)```(?:java)?(?:\\n|\n)(.*?)(?:\\n|\n)```', message, re.DOTALL
    )
    if before_match:
        code = before_match.group(1).strip()
        # Replace literal \n with actual newlines if present
        if '\\n' in code:
            code = code.replace('\\n', '\n')

        # Extract import statements from the code
        # Pattern: import package.name.ClassName;
        import_pattern = r'import\s+[\w.]+\s*;'
        found_imports = re.findall(import_pattern, code)
        imports.extend(found_imports)

    return imports


def extract_config_content_from_message(message: str) -> str:
    """
    Extract configuration file content from a rule message's "Before:" section.

    Args:
        message: Rule message (may contain Before/After code examples)

    Returns:
        Configuration content as string, or empty string if not found
    """
    if not message or 'Before:' not in message:
        return ''

    # Look for code blocks after "Before:"
    before_match = re.search(
        r'Before:(?:\\n|\n)```(?:\\n|\n)?(.*?)(?:\\n|\n)```', message, re.DOTALL
    )
    if before_match:
        content = before_match.group(1).strip()
        # Replace literal \n with actual newlines if present
        if '\\n' in content:
            content = content.replace('\\n', '\n')
        # Remove comment markers if the example shows commented config
        content = re.sub(r'^\s*#\s*', '', content, flags=re.MULTILINE)
        return content

    return ''


def create_missing_config_files(
    rules: list, test_data_dir, language: str, existing_config: dict = None
) -> list:
    """
    Create configuration files for rules that need them but weren't generated by LLM.

    Args:
        rules: List of rule dictionaries
        test_data_dir: Path to test data directory
        language: Programming language
        existing_config: Config file info from LLM (if any)

    Returns:
        List of created config file paths
    """
    if language != 'java':
        return []

    created_files = []

    for rule in rules:
        when = rule.get('when', {})
        if 'builtin.filecontent' not in when:
            continue

        filecontent = when['builtin.filecontent']
        file_pattern = filecontent.get('filePattern', '')
        pattern = filecontent.get('pattern', '')
        message = rule.get('message', '')

        # Check if this needs a config file
        # Check for file extensions (without the dot since pattern may have \.)
        needs_config = any(
            ext in file_pattern for ext in ['properties', 'yaml', 'yml', 'factories', 'xml']
        )

        if not needs_config:
            continue

        # Determine config file type and name
        # Note: Don't check for '.' prefix since filePattern may have escaped dots (\.)
        if 'properties' in file_pattern and 'spring.factories' not in file_pattern:
            config_type = 'properties'
            config_name = 'application.properties'
            config_dir = test_data_dir / 'src' / 'main' / 'resources'
        elif 'spring.factories' in file_pattern or 'factories' in file_pattern:
            config_type = 'properties'
            config_name = 'spring.factories'
            config_dir = test_data_dir / 'src' / 'main' / 'resources' / 'META-INF'
        elif 'yaml' in file_pattern or 'yml' in file_pattern:
            config_type = 'yaml'
            config_name = 'application.yaml'
            config_dir = test_data_dir / 'src' / 'main' / 'resources'
        else:
            continue

        config_path = config_dir / config_name

        # Skip if config file already exists
        if config_path.exists():
            continue

        # Extract content from "Before:" example
        content = extract_config_content_from_message(message)
        if not content:
            # If no Before example, try to construct minimal config from pattern
            if config_type == 'properties':
                # For properties, use the pattern as a key with a placeholder value
                content = f"{pattern}=8KB\n"
            else:
                content = f"# {rule['ruleID']}\n"

        # Ensure the pattern appears in the config
        # Note: pattern might be a regex, so unescape common regex chars for config files
        if pattern and pattern not in content:
            # Remove regex escaping (e.g., \. -> .)
            unescaped_pattern = pattern.replace('\\\\', '\\').replace('\\.', '.')
            if config_type == 'properties':
                content = f"{unescaped_pattern}=8KB\n" + content
            else:
                content = f"{unescaped_pattern}: value\n" + content

        # Create the config file
        config_dir.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            f.write(content)

        created_files.append(config_path)

    return created_files


def create_file_based_patterns(rules: list, test_data_dir, language: str) -> list:
    """
    Create files for file-name based patterns (e.g., banner.png, *.gif).

    Args:
        rules: List of rule dictionaries
        test_data_dir: Path to test data directory
        language: Programming language

    Returns:
        List of created file paths
    """
    created_files = []

    for rule in rules:
        when = rule.get('when', {})
        if 'builtin.filecontent' not in when:
            continue

        filecontent = when['builtin.filecontent']
        file_pattern = filecontent.get('filePattern', '')
        pattern = filecontent.get('pattern', '')

        # Check if pattern is a file name pattern
        # (both pattern and filePattern are the same and look like file names)
        if pattern != file_pattern:
            continue

        # Check if it's a file extension pattern (e.g., banner.(gif|jpg|png))
        file_match = re.match(r'([^.]+)\\.?\(([\w|]+)\)', pattern)
        if file_match:
            base_name = file_match.group(1)
            extensions = file_match.group(2).split('|')
            # Create a file with the first extension
            ext = extensions[0]
            filename = f"{base_name}.{ext}"

            # Determine directory based on language
            if language == 'java':
                file_dir = test_data_dir / 'src' / 'main' / 'resources'
            elif language == 'go':
                file_dir = test_data_dir
            elif language == 'typescript':
                file_dir = test_data_dir / 'src'
            else:
                file_dir = test_data_dir

            file_dir.mkdir(parents=True, exist_ok=True)
            file_path = file_dir / filename

            # Create a minimal file
            # For images, create an empty file (static analyzer only checks existence)
            with open(file_path, 'wb') as f:
                f.write(b'')  # Empty file

            created_files.append(file_path)

    return created_files


def inject_missing_java_imports(source_code: str, patterns_to_test: list, rules: list) -> str:
    """
    Post-process Java source code to inject missing import statements.

    This ensures that even if the AI doesn't include required imports,
    they get added automatically for IMPORT location rules.

    Args:
        source_code: Generated Java source code
        patterns_to_test: List of pattern dictionaries from extract_patterns_from_rules
        rules: List of rules with messages

    Returns:
        Java source code with missing imports injected
    """
    # Collect all required imports from IMPORT location patterns
    required_imports = set()

    for pattern_group in patterns_to_test:
        # Each pattern_group has a 'patterns' list with sub-patterns
        if 'patterns' in pattern_group:
            for pattern in pattern_group['patterns']:
                if pattern.get('location') == 'IMPORT' and pattern.get('code_hint'):
                    # code_hint contains the full import statements
                    imports = pattern['code_hint'].split('\n')
                    for imp in imports:
                        imp = imp.strip()
                        if imp and imp.startswith('import '):
                            required_imports.add(imp)

    if not required_imports:
        return source_code  # No imports to inject

    # Check which imports are missing
    missing_imports = []
    for required_import in required_imports:
        if required_import not in source_code:
            missing_imports.append(required_import)

    if not missing_imports:
        return source_code  # All imports already present

    # Inject missing imports after package declaration
    # Find package declaration
    package_match = re.search(r'(package\s+[\w.]+\s*;)', source_code)

    if package_match:
        package_end = package_match.end()

        # Build import block with comments indicating which rules need them
        import_block = '\n\n// Auto-injected imports for IMPORT location rules\n'
        for imp in sorted(missing_imports):
            import_block += f'{imp}\n'

        # Inject imports after package declaration
        source_code = source_code[:package_end] + import_block + source_code[package_end:]

    return source_code


def generate_code_hint_from_pattern(
    pattern: str, language: str, description: str = '', message: str = ''
) -> str:
    """
    Generate a code example hint from a regex pattern or rule message.

    Args:
        pattern: Regex pattern from builtin.filecontent
        language: Programming language
        description: Rule description
        message: Rule message (may contain Before/After code examples)

    Returns:
        Code example string
    """
    # For languages other than TypeScript/Go, don't generate hints
    if language not in ['typescript', 'go']:
        return None

    # Normalize double-escaped patterns (e.g., \\\\b -> \\b)
    # Some rule generators double-escape backslashes, resulting in \\\\b instead of \\b
    if '\\\\b' in pattern or '\\\\.' in pattern or '\\\\(' in pattern or '\\\\{' in pattern:
        # Replace double backslashes with single backslashes for regex metacharacters
        pattern = pattern.replace('\\\\b', '\\b')
        pattern = pattern.replace('\\\\B', '\\B')
        pattern = pattern.replace('\\\\d', '\\d')
        pattern = pattern.replace('\\\\D', '\\D')
        pattern = pattern.replace('\\\\s', '\\s')
        pattern = pattern.replace('\\\\S', '\\S')
        pattern = pattern.replace('\\\\w', '\\w')
        pattern = pattern.replace('\\\\W', '\\W')
        pattern = pattern.replace('\\\\.', '\\.')
        pattern = pattern.replace('\\\\(', '\\(')
        pattern = pattern.replace('\\\\)', '\\)')
        pattern = pattern.replace('\\\\{', '\\{')
        pattern = pattern.replace('\\\\}', '\\}')
        pattern = pattern.replace('\\\\[', '\\[')
        pattern = pattern.replace('\\\\]', '\\]')

    # FIRST: Try to extract code from the message's "Before:" section
    # This is the most reliable source of correct JSX
    if message:
        # Look for code blocks after "Before:"
        # Handle both actual newlines and literal \n (backslash-n) in the message
        # Some YAML files have literal \n sequences instead of actual newlines
        before_match = re.search(
            r'Before:(?:\\n|\n)```(?:\\n|\n)(.*?)(?:\\n|\n)```', message, re.DOTALL
        )
        if before_match:
            code = before_match.group(1).strip()
            # Replace literal \n with actual newlines if present
            if '\\n' in code:
                code = code.replace('\\n', '\n')
            # Skip if contains template variables ({{ }})
            if '{{' not in code and '}}' not in code:
                # CRITICAL: Prefer single-line code for line-by-line matching
                # If code contains newlines, skip it and use pattern-based generation instead
                # This ensures tests work with Konveyor's line-by-line builtin.filecontent matching
                if '\n' in code:
                    # Code spans multiple lines, skip and use pattern-based generation
                    pass
                elif pattern:
                    try:
                        # Use actual regex matching to validate single-line code
                        if re.search(pattern, code):
                            # Pattern matches, return this code
                            return code
                        else:
                            # Pattern doesn't match, fall back to pattern-based generation
                            pass
                    except re.error:
                        # Invalid regex pattern, fall back to simple check
                        simple_pattern = pattern.replace('\\', '').replace('.', '')
                        if simple_pattern in code:
                            return code
                else:
                    # No pattern to validate, return the code
                    return code

    # Fallback: Try to extract patterns from the regex

    # Pattern 1: render with callback - render\([^,]+,[^,]+,\s*\(
    # This pattern matches render with 3 args where the 3rd is a callback starting with (
    if pattern.startswith('render\\(') and ',\\s*\\(' in pattern:
        # This is render with a callback function (single line for line-by-line matching)
        return "render(<App tab=\"home\" />, container, () => { console.log('rendered'); });"

    # Pattern 2: renderToString with Suspense - renderToString\([^)]*<Suspense
    if 'renderToString' in pattern and 'Suspense' in pattern:
        # Single line for line-by-line matching
        return "renderToString(<Suspense fallback={<Loading />}><App /></Suspense>);"

    # Pattern 3: setTimeout with multiple setState - setTimeout\([^{]*\{[^}]*set...
    if 'setTimeout' in pattern and 'set[A-Z]' in pattern:
        # Multiple setState calls in setTimeout (single line for line-by-line matching)
        # Use old-style function syntax to match pattern [^)]* (no closing parens allowed)
        return "setTimeout(function() { setCount(c + 1); setFlag(!f); }, 1000);"

    # Pattern 4: Interface with Props - interface\s+[A-Za-z0 - 9_]+Props\s*\{[^}]*\}
    if 'interface' in pattern and 'Props' in pattern:
        # TypeScript interface (single line for line-by-line matching)
        return "interface ButtonProps { onClick: () => void; disabled?: boolean; }"

    # Pattern 5: IS_REACT_ACT_ENVIRONMENT - needs to be referenced as an identifier,
    # not property access
    if pattern == 'IS_REACT_ACT_ENVIRONMENT':
        # Use as identifier, not global.IS_REACT_ACT_ENVIRONMENT (which is property access)
        return "const testEnv = IS_REACT_ACT_ENVIRONMENT;"

    # Pattern 4: Method calls like ReactDOM\.render\( or obj\.method\(
    # Match: ObjectName.methodName( or functionName(
    method_call_match = re.match(r'([A-Za-z_][\w.]*)\\\.([A-Za-z_]\w*)\\?\(', pattern)
    if method_call_match:
        obj_name = method_call_match.group(1).replace('\\', '')  # Remove regex escapes
        method_name = method_call_match.group(2)

        # Generate appropriate code based on the pattern
        if 'ReactDOM' in obj_name and method_name == 'render':
            return "ReactDOM.render(<App />, container);"
        elif 'ReactDOM' in obj_name and method_name == 'hydrate':
            return "ReactDOM.hydrate(<App />, container);"
        elif method_name == 'unmountComponentAtNode':
            return "ReactDOM.unmountComponentAtNode(container);"
        else:
            # Generic method call
            return f"{obj_name}.{method_name}();"

    # Pattern 5: Standalone function calls like render\( or hydrate\(
    function_call_match = re.match(r'([A-Za-z_]\w*)\\?\(', pattern)
    if function_call_match:
        func_name = function_call_match.group(1)
        # Generate appropriate code based on function name
        if func_name in ['render', 'hydrate']:
            # These are likely from react-dom imports
            return f"{func_name}(<App />, container);"
        else:
            return f"{func_name}();"

    # Pattern 3: JSX tag patterns <ComponentName[^>]*\battribute['"]value['"]*>
    # Don't require closing > since patterns often don't include it
    jsx_match = re.search(r'<(\w+)(.*)', pattern)
    if jsx_match:
        component = jsx_match.group(1)
        attributes_pattern = jsx_match.group(2)

        # Extract specific attributes
        attrs = []

        # Look for variant="value" or similar explicit value patterns
        variant_match = re.search(r'\\bvariant=.*?[\'"](\w+)[\'"]', attributes_pattern)
        if variant_match:
            attrs.append(f'variant="{variant_match.group(1)}"')

        # Look for word-boundary props (e.g., \bisActive\b, \bfrom\b)
        # Extract all \bword\b patterns from the attributes
        # Note: attributes_pattern is a string like "[^>]*\bisActive\b"
        # where \b is the literal backslash character followed by 'b'
        # Use r'\\b' to match this two-character sequence
        prop_matches = re.findall(r'\\b(\w+)\\b', attributes_pattern)
        for prop in prop_matches:
            # Skip if already added
            if any(prop in attr for attr in attrs):
                continue

            # Determine appropriate value based on prop name
            if prop.startswith('is') or prop.startswith('has') or prop.startswith('should'):
                # Boolean props - no value needed in JSX
                attrs.append(prop)
            elif prop in ['variant', 'size', 'position', 'align']:
                # Already handled by variant_match or needs explicit value
                attrs.append(f'{prop}="default"')
            elif prop == 'from':
                # Common prop that needs a value (like in Import component)
                attrs.append('from="source"')
            elif prop == 'to':
                # Navigation prop
                attrs.append('to="/path"')
            elif prop in ['onClick', 'onChange', 'onToggle', 'onSelect']:
                # Event handler props
                attrs.append(f'{prop}={{() => {{}}}}')
            else:
                # Generic prop with string value
                attrs.append(f'{prop}="value"')

        # Build example
        attr_str = ' ' + ' '.join(attrs) if attrs else ''

        # Check if it's self-closing or has children
        if 'icon' in pattern.lower() or 'children' in pattern.lower():
            return f'<{component}{attr_str}>\n  <SomeIcon />\n</{component}>'
        else:
            return f'<{component}{attr_str}>Content</{component}>'

    # Pattern 4: Import patterns
    import_match = re.search(r'import.*?from.*?[\'"](@[\w/-]+)[\'"]', pattern)
    if import_match:
        package = import_match.group(1)
        return f'import {{ Component }} from "{package}";'

    # Pattern 5: Simple alternation patterns (e.g., "Promise|Symbol|Object\.assign")
    # These are common for detecting usage of specific identifiers
    if '|' in pattern and not re.search(r'[<>(){}\[\]]', pattern):
        # This looks like a simple alternation of identifiers
        # Split by | and clean up alternatives
        alternatives = [alt.replace('\\', '').strip() for alt in pattern.split('|')]

        # Try to generate code that uses all alternatives in one line if they're related
        if (
            'Promise' in alternatives
            and 'Symbol' in alternatives
            and 'Object.assign' in alternatives
        ):
            # Modern browser features - use all in one statement
            return (
                "new Promise((resolve) => { Symbol('id'); Object.assign({}, {}); resolve(true); });"
            )
        elif 'Promise' in alternatives:
            return "new Promise((resolve) => resolve('data'));"
        elif 'Symbol' in alternatives:
            return "const uniqueKey = Symbol('unique');"
        elif any(alt.startswith('Object.') for alt in alternatives):
            return "Object.assign({}, { theme: 'dark' }, { locale: 'en' });"
        else:
            # Use the first alternative generically
            first_alt = alternatives[0]
            return f"const result = {first_alt};"

    # Go-specific patterns
    if language == 'go':
        # Pattern 1: interface{} - the empty interface
        if pattern == r'interface{}' or pattern == 'interface{}':
            return "func PrintAny(v interface{}) { fmt.Println(v) }"

        # Pattern 2: Build constraints //+build
        if pattern == r'//\+build' or '//+build' in pattern:
            return "//+build linux darwin"

        # Pattern 3: Simple literal patterns - just use them as-is in a function
        # For Go, many patterns are simple literals that should appear in the code
        if not re.search(r'[\\()\[\]{}|+*?]', pattern):
            # This is a simple literal string (no regex special chars)
            # Generate a comment or code that contains this literal
            if '//' in pattern:
                # It's a comment pattern
                return pattern
            else:
                # It's a code pattern - use it in a variable or function
                return f"var example = {pattern}"

    return None


def build_test_generation_prompt(
    rules: list, source: str, target: str, guide_url: str, language: str
) -> str:
    """
    Build prompt for LLM to generate test application code.

    Args:
        rules: List of rule dictionaries
        source: Source framework/version
        target: Target framework/version
        guide_url: URL to migration guide
        language: Programming language

    Returns:
        Prompt string
    """
    lang_config = get_language_config(language)
    patterns = extract_patterns_from_rules(rules, language)

    # Build patterns summary with specific code examples
    patterns_list = []
    has_config_files = False
    config_file_type = 'properties'  # default
    config_file_name = None
    config_file_path = None

    for p in patterns:
        pattern_text = f"- Rule {p['ruleID']}: {p['description']}"

        # Check if any pattern needs config files or has Java imports
        has_java_imports = False
        has_nodejs_referenced = False
        for pattern in p.get('patterns', []):
            if pattern.get('is_config_file'):
                has_config_files = True
                config_file_type = pattern.get('config_type', 'properties')
                config_file_name = pattern.get(
                    'config_file_name', f'application.{config_file_type}'
                )
                config_file_path = pattern.get('config_file_path', '')
                # Add config file specific instruction
                pattern_obj = pattern.get('pattern', '')
                if config_file_path:
                    pattern_text += (
                        f"\n  **MUST BE IN CONFIG FILE ({config_file_type}) "
                        f"at {config_file_path}:** {pattern_obj}"
                    )
                else:
                    pattern_text += (
                        f"\n  **MUST BE IN CONFIG FILE ({config_file_type}) "
                        f"named {config_file_name}:** {pattern_obj}"
                    )

            # Check for Java imports
            if (
                pattern.get('provider') == 'java'
                and pattern.get('location') == 'IMPORT'
                and pattern.get('code_hint')
            ):
                has_java_imports = True
                pattern_text += (
                    "\n\n  **YOU MUST INCLUDE THESE EXACT IMPORT STATEMENTS:**\n"
                    f"  ```java\n  // {p['ruleID']}\n  {pattern['code_hint']}\n  ```"
                )

            # Check for nodejs.referenced (TypeScript/JavaScript)
            if pattern.get('provider') == 'nodejs' and language == 'typescript':
                has_nodejs_referenced = True
                api_name = pattern.get('pattern', '')
                # Extract from message if available to get import location
                message = p.get('message', '')
                import_statement = ''
                if 'from \'react\'' in message or 'from "react"' in message:
                    import_statement = f"import {{ {api_name} }} from 'react';"
                elif 'from \'react-dom\'' in message or 'from "react-dom"' in message:
                    import_statement = f"import {{ {api_name} }} from 'react-dom';"
                elif 'from \'react-dom/server\'' in message or 'from "react-dom/server"' in message:
                    import_statement = f"import {{ {api_name} }} from 'react-dom/server';"
                else:
                    # Default to react
                    import_statement = f"import {{ {api_name} }} from 'react';"

                pattern_text += (
                    "\n\n  **CRITICAL - nodejs.referenced pattern:**\n"
                    f"  You MUST import AND use `{api_name}` in your code.\n"
                    f"  ```tsx\n  // {p['ruleID']}\n  {import_statement}\n  \n"
                    f"  // Then CALL or USE {api_name} somewhere in your component code\n"
                    f"  // Example: const result = {api_name}(...);\n  ```"
                )

            # Check for builtin.filecontent patterns
            if pattern.get('provider') == 'builtin' and 'pattern' in pattern:
                pattern_value = pattern.get('pattern', '')

                # Check for import component patterns
                if pattern.get('import_component'):
                    import_component = pattern.get('import_component')
                    # Extract the package path from the pattern
                    import_package = '@patternfly/react-core/v5'  # default
                    if '@patternfly/react-' in pattern_value:
                        import_package = '@patternfly/react-core/v5'

                    pattern_text += (
                        f"\n\n  **CRITICAL - Import pattern:**\n"
                        f"  You MUST import `{import_component}` from the v5 path:\n"
                        f"  ```tsx\n  // {p['ruleID']}\n  "
                        f"import {{ {import_component} }} from '{import_package}';\n  ```\n"
                        f"  And then USE the `{import_component}` component in JSX."
                    )
                # Extract "Before:" example from message if available
                message = p.get('message', '')
                before_example = None
                if 'Before:' in message:
                    try:
                        before_start = message.index('Before:')
                        after_start = (
                            message.index('After:') if 'After:' in message else len(message)
                        )
                        before_section = message[before_start:after_start]
                        # Extract code block from Before section
                        if '```' in before_section:
                            code_start = before_section.index('```') + 3
                            # Skip language identifier if present
                            if '\n' in before_section[code_start:]:
                                code_start = before_section.index('\n', code_start) + 1
                            code_end = before_section.index('```', code_start)
                            before_example = before_section[code_start:code_end].strip()
                    except (ValueError, IndexError):
                        pass

                if before_example and pattern_value:
                    pattern_text += (
                        f"\n\n  **Pattern to detect:** `{pattern_value}`\n"
                        f"  **You MUST include code that matches this pattern:**\n"
                        f"  ```\n  // {p['ruleID']}\n  {before_example}\n  ```"
                    )

        # Add code hint if available (for code-based rules)
        if p.get('code_hint') and not has_java_imports and not has_nodejs_referenced:
            if language == 'typescript':
                pattern_text += (
                    "\n\n  **YOU MUST GENERATE THIS EXACT JSX CODE:**\n"
                    f"  ```tsx\n  // {p['ruleID']}\n  {p['code_hint']}\n  ```"
                )
        elif p.get('component') and not has_nodejs_referenced:
            pattern_text += (
                f"\n  Component: {p['component']} (MUST be used in JSX, not just imported)"
            )

        patterns_list.append(pattern_text)

    patterns_summary = "\n\n".join(patterns_list)

    # Build config file instructions for Java
    config_file_instructions = ""
    config_file_name = config_file_name if config_file_name else f'application.{config_file_type}'
    config_file_path = (
        config_file_path if config_file_path else f'src/main/resources/{config_file_name}'
    )

    if has_config_files and language == 'java':
        config_file_instructions = f"""
3. **{config_file_name}** - Configuration file with deprecated properties:
   - Location: {config_file_path}
   - CRITICAL: The deprecated property patterns marked as "MUST BE IN CONFIG FILE"
     below MUST appear in this file
   - Do NOT use @Value annotations in Java code for these patterns
   - Include the EXACT deprecated property names from the "Before:" examples
     in the rule messages
   - Format the properties correctly for {config_file_type} format
   - Include actual values for each deprecated property
   - Example: If pattern is spring\\.data\\.cassandra\\., include properties like:
     spring.data.cassandra.contact-points=localhost
     spring.data.cassandra.port=9042
"""

    # Load language-specific instructions template
    # Map language to template file (javascript and typescript use same template)
    template_name = language
    if language in ['javascript', 'typescript']:
        template_name = 'typescript'

    lang_template = jinja_env.get_template(f'lang/{template_name}.j2')
    lang_instructions = lang_template.render(
        build_file=lang_config['build_file'],
        main_file=lang_config['main_file'],
        source=source,
        target=target,
        config_file_instructions=config_file_instructions,
    )

    # Render main prompt template
    main_template = jinja_env.get_template('main.j2')
    prompt = main_template.render(
        language=language,
        source=source,
        target=target,
        guide_url=guide_url,
        patterns_summary=patterns_summary,
        lang_instructions=lang_instructions,
        build_file=lang_config['build_file'],
        build_file_type=lang_config['build_file_type'],
        main_file=lang_config['main_file'],
        main_file_type=lang_config['main_file_type'],
        has_config_files=has_config_files,
        config_file_type=config_file_type,
        config_file_name=config_file_name,
    )

    return prompt


def extract_code_blocks(response: str, language: str) -> dict:
    """
    Extract build file, source file, and config file from LLM response.

    Args:
        response: LLM response text
        language: Programming language

    Returns:
        Dict with build_file, source_file, and config_file keys
    """
    lang_config = get_language_config(language)
    result = {'build_file': None, 'source_file': None, 'config_file': None}

    # Try to extract code blocks
    # Pattern: ```type\n content \n```
    code_blocks = re.findall(r'```(\w+)\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)

    for block_type, content in code_blocks:
        content = content.strip()

        # Special handling for Go: first 'go' block is build file, second is source file
        if block_type.lower() == 'go':
            if not result['build_file']:
                result['build_file'] = content
            elif not result['source_file']:
                result['source_file'] = content
        # Match build file types (excluding 'go' since it's handled above)
        elif block_type.lower() in ['xml', 'json', 'text', 'txt', 'toml']:
            if not result['build_file']:
                result['build_file'] = content
        # Match config file types
        elif block_type.lower() in ['properties', 'yaml', 'yml']:
            if not result['config_file']:
                # Try to extract filename from content (first line might have filename as comment)
                # or infer from block type
                filename = None
                first_line = content.split('\n')[0].strip() if content else ''
                # Check if first line looks like a filename comment or path
                if first_line.startswith('#') or first_line.startswith('//'):
                    potential_name = first_line.lstrip('#/ ').strip()
                    if '.' in potential_name and not potential_name.startswith('Rule'):
                        filename = potential_name.split('/')[-1]  # Extract just filename from path

                if not filename:
                    filename = f'application.{block_type.lower()}'

                result['config_file'] = {
                    'type': block_type.lower(),
                    'content': content,
                    'filename': filename,
                }
        # Match source file types ('go' is handled specially above)
        elif block_type.lower() in [
            'java',
            'typescript',
            'tsx',
            'ts',
            'python',
            'py',
            'javascript',
            'jsx',
            'js',
        ]:
            if not result['source_file']:
                result['source_file'] = content

    # Fallback: try to find files by name/comment
    if not result['build_file']:
        build_pattern = rf'```\w*\s*(?:<!--\s*)?{re.escape(lang_config["build_file"])}.*?```'
        build_match = re.search(build_pattern, response, re.DOTALL | re.IGNORECASE)
        if build_match:
            # Extract content between ```
            content_match = re.search(r'```\w*\s*(.*?)\s*```', build_match.group(0), re.DOTALL)
            if content_match:
                result['build_file'] = content_match.group(1).strip()

    if not result['source_file']:
        source_pattern = rf'```\w*\s*(?://|#)?\s*{re.escape(lang_config["main_file"])}.*?```'
        source_match = re.search(source_pattern, response, re.DOTALL | re.IGNORECASE)
        if source_match:
            content_match = re.search(r'```\w*\s*(.*?)\s*```', source_match.group(0), re.DOTALL)
            if content_match:
                result['source_file'] = content_match.group(1).strip()

    return result


def validate_generated_language(code_blocks: dict, expected_language: str) -> tuple[bool, str]:
    """
    Validate that generated code matches the expected language.

    Args:
        code_blocks: Dict with 'build_file' and 'source_file' keys
        expected_language: Expected language (e.g., 'typescript', 'java')

    Returns:
        Tuple of (is_valid, error_message)
    """
    source_file = code_blocks.get('source_file', '')
    build_file = code_blocks.get('build_file', '')

    if not source_file:
        return False, "No source file generated"

    # Check for Java code when TypeScript was requested
    if expected_language == 'typescript':
        java_indicators = [
            'package com.',
            'import org.springframework',
            '@SpringBootApplication',
            '@RestController',
            '@Controller',
            'public class',
            'public static void main',
            'import javax.',
            'import jakarta.',
        ]

        for indicator in java_indicators:
            if indicator in source_file:
                return False, (
                    f"LANGUAGE MISMATCH: Generated Java code (found '{indicator}') "
                    f"when {expected_language} was requested. "
                    f"Source file starts with: {source_file[:200]}"
                )

        # Check for TypeScript/React indicators
        typescript_indicators = [
            'import React',
            'import {',
            'from \'react\'',
            'from "react"',
            'export default',
            'export function',
            'export const',
            '=>',
            '<div',
            '<App',
        ]

        has_typescript = any(indicator in source_file for indicator in typescript_indicators)
        if not has_typescript:
            return False, (
                f"Generated code doesn't look like {expected_language}. "
                f"Source file starts with: {source_file[:200]}"
            )

        # Check build file for package.json content
        if build_file and '<project' in build_file:
            return False, (
                "LANGUAGE MISMATCH: Generated pom.xml (Maven/Java build file) "
                f"when package.json was expected for {expected_language}"
            )

    # Check for TypeScript code when Java was requested
    elif expected_language == 'java':
        typescript_indicators = [
            'import React',
            'from \'react\'',
            'from "react"',
            'export default',
            'const ',
            'let ',
        ]

        for indicator in typescript_indicators:
            if indicator in source_file:
                return False, (
                    f"LANGUAGE MISMATCH: Generated TypeScript/JavaScript code "
                    f"(found '{indicator}') when {expected_language} was requested"
                )

    return True, ""


def create_directory_structure(output_dir: Path, language: str):
    """
    Create language-specific directory structure.

    Args:
        output_dir: Base output directory
        language: Programming language
    """
    lang_config = get_language_config(language)

    # Create source directory
    src_dir = output_dir / lang_config['source_dir']
    src_dir.mkdir(parents=True, exist_ok=True)

    return src_dir


def sanitize_dir_name(name: str) -> str:
    """
    Sanitize directory name to avoid analyzer's default exclude patterns.

    The builtin provider excludes: node_modules, vendor, .git, dist, build, target, .venv, venv
    Replace problematic words in directory names to prevent exclusion.

    Args:
        name: Original directory name

    Returns:
        Sanitized directory name
    """
    replacements = {
        'build': 'builds',
        'target': 'targets',
        'vendor': 'vendors',
        'dist': 'distribution',
    }

    result = name
    for bad, good in replacements.items():
        # Replace word when surrounded by hyphens or at boundaries
        result = result.replace(f'{bad}-', f'{good}-')
        result = result.replace(f'-{bad}', f'-{good}')
        if result == bad:
            result = good

    return result


def generate_test_yaml(
    rule_file_path: Path, data_dir_name: str, rules: list, output_dir: Path
) -> Path:
    """
    Generate a Konveyor test YAML file.

    Args:
        rule_file_path: Path to the rule YAML file
        data_dir_name: Name of the data directory (e.g., "button")
        rules: List of rule dictionaries
        output_dir: Output directory for tests

    Returns:
        Path to created test YAML file
    """
    # Extract rule IDs
    rule_ids = [rule.get('ruleID') for rule in rules if rule.get('ruleID')]

    # Determine providers from rules
    def extract_providers(cond):
        """Helper to extract providers from a condition."""
        found = set()
        if 'java.referenced' in cond or 'java.dependency' in cond:
            found.add('java')
        if 'nodejs.referenced' in cond or 'nodejs.dependency' in cond:
            found.add('nodejs')
        if 'builtin.file' in cond or 'builtin.filecontent' in cond:
            found.add('builtin')
        if 'go.referenced' in cond or 'go.dependency' in cond:
            found.add('go')
        if 'python.referenced' in cond or 'python.dependency' in cond:
            found.add('python')

        # If only builtin provider, try to infer language-specific provider from filePattern
        if found == {'builtin'}:
            builtin_cond = cond.get('builtin.filecontent') or cond.get('builtin.file', {})
            file_pattern = builtin_cond.get('filePattern', '')

            # Add language-specific provider based on filePattern
            if any(
                pattern in file_pattern
                for pattern in ['.ts', '.tsx', '.js', '.jsx', '(j|t)s', 'jsx?', 'tsx?']
            ):
                found.add('nodejs')
            elif '.java' in file_pattern:
                found.add('java')
            elif '.go' in file_pattern:
                found.add('go')
            elif '.py' in file_pattern:
                found.add('python')

        return found

    providers = set()
    for rule in rules:
        when = rule.get('when', {})

        # Check for 'and' conditions
        if 'and' in when:
            and_conditions = when['and'] if isinstance(when['and'], list) else [when['and']]
            for cond in and_conditions:
                providers.update(extract_providers(cond))
        # Check for 'or' conditions
        elif 'or' in when:
            or_conditions = when['or'] if isinstance(when['or'], list) else [when['or']]
            for cond in or_conditions:
                providers.update(extract_providers(cond))
        # Check direct conditions
        else:
            providers.update(extract_providers(when))

    # Default to java and builtin if we can't determine
    if not providers:
        providers = {'java', 'builtin'}

    # Write test YAML file first to determine location
    test_file_name = rule_file_path.stem + '.test.yaml'
    test_file_path = output_dir / test_file_name

    # Calculate relative path from test file to rule file
    # Use pathlib to compute the relative path automatically
    try:
        # Get absolute paths
        test_abs = test_file_path.resolve().parent
        rule_abs = rule_file_path.resolve()

        # Calculate relative path from test directory to rule file
        relative_rules_path = os.path.relpath(rule_abs, test_abs)
    except (ValueError, OSError):
        # Fallback: assume standard structure (tests/data/<concern>/ → rules/)
        # Count how many levels deep we are from a common root
        # If output_dir has "data" in it, we're likely in tests/data/<concern>/
        # Otherwise, we're in tests/
        if 'data' in str(output_dir):
            relative_rules_path = f'../../../rules/{rule_file_path.name}'
        else:
            relative_rules_path = f'../rules/{rule_file_path.name}'

    # Build test structure
    test_data = {
        'rulesPath': relative_rules_path,
        'providers': [
            {'name': provider, 'dataPath': f'./data/{data_dir_name}'}
            for provider in sorted(providers)
        ],
        'tests': [
            {'ruleID': rule_id, 'testCases': [{'name': 'tc - 1', 'hasIncidents': {'atLeast': 1}}]}
            for rule_id in rule_ids
        ],
    }

    with open(test_file_path, 'w') as f:
        yaml.dump(test_data, f, default_flow_style=False, sort_keys=False)

    return test_file_path


def run_kantra_tests(output_dir: Path) -> dict:
    """
    Run kantra tests and parse results.

    Args:
        output_dir: Directory containing test YAML files

    Returns:
        Dict with test results including failures and debug paths
    """
    import subprocess

    print(f"\n{'=' * 70}")
    print("Running kantra tests...")
    print(f"{'=' * 70}")

    # Find all test files
    test_files = list(output_dir.glob('*.test.yaml'))
    if not test_files:
        print("No test files found")
        return {'passed': 0, 'total': 0, 'failures': [], 'exit_code': 1}

    # Run kantra test with explicit file list (use just filenames since cwd is set)
    # Validate filenames to prevent injection (though subprocess.run with list is safe)
    safe_filenames = []
    for f in test_files:
        # Ensure filename is safe (no path traversal, no shell metacharacters)
        if not f.name.endswith('.test.yaml') or '/' in f.name or '\\' in f.name:
            print(f"⚠ Skipping suspicious filename: {f.name}")
            continue
        safe_filenames.append(f.name)

    if not safe_filenames:
        print("No valid test files after validation")
        return {'passed': 0, 'total': 0, 'failures': [], 'exit_code': 1}

    result = subprocess.run(
        ['kantra', 'test'] + safe_filenames,
        cwd=output_dir,
        capture_output=True,
        text=True,
        timeout=config.KANTRA_TIMEOUT_SECONDS,
    )

    output = result.stdout + result.stderr
    print(output)

    # Parse summary
    summary_match = re.search(r'Rules Summary:\s+(\d+)/(\d+)', output)
    if summary_match:
        passed = int(summary_match.group(1))
        total = int(summary_match.group(2))
    else:
        passed = 0
        total = 0

    # Extract failed rules with debug paths
    # Look for rule IDs (format: source-to-target-NNNNN) followed by 0/1 PASSED and debug path
    # Use [\w-]+ to match word chars AND hyphens (for multi-part source/target names)
    failures = []
    for match in re.finditer(
        r'([\w-]+-\d{5})\s+0/1\s+PASSED.*?find debug data in (/[^\s]+)', output, re.DOTALL
    ):
        rule_id = match.group(1)
        debug_path = match.group(2).strip()
        failures.append({'rule_id': rule_id, 'debug_path': debug_path})

    return {'passed': passed, 'total': total, 'failures': failures, 'exit_code': result.returncode}


def analyze_test_failure(debug_path: str) -> dict:
    """
    Analyze test failure from kantra debug data.

    Args:
        debug_path: Path to kantra debug directory

    Returns:
        Dict with failure details (pattern, actual code, etc.)
    """
    debug_dir = Path(debug_path)
    if not debug_dir.exists():
        return {'error': 'Debug directory not found'}

    output_yaml = debug_dir / 'output.yaml'
    rules_yaml = debug_dir / 'rules.yaml'

    if not output_yaml.exists() or not rules_yaml.exists():
        return {'error': 'Debug files missing'}

    # Read debug data
    try:
        with open(output_yaml) as f:
            output_data = yaml.safe_load(f)

        # Validate output data structure
        if not isinstance(output_data, (list, dict)):
            return {'error': f'Invalid YAML structure in {output_yaml}: expected list or dict'}

        with open(rules_yaml) as f:
            rules_data = yaml.safe_load(f)

        # Validate rules data structure
        if not isinstance(rules_data, (list, dict)):
            return {'error': f'Invalid YAML structure in {rules_yaml}: expected list or dict'}

    except yaml.YAMLError as e:
        return {'error': f'YAML parsing error: {e}'}
    except (IOError, OSError) as e:
        return {'error': f'Error reading file: {e}'}

    # Find unmatched rules - kantra output format is:
    # - name: konveyor-analysis
    #   unmatched:
    #   - rule-id - 1
    #   - rule-id - 2
    unmatched = []

    if isinstance(output_data, list) and len(output_data) > 0:
        # Direct access to unmatched list (no 'violations' wrapper)
        unmatched = output_data[0].get('unmatched', [])

    if not unmatched:
        return {'error': 'No unmatched rules found'}

    rule_id = unmatched[0] if isinstance(unmatched, list) else unmatched

    # Find rule pattern
    rule = None
    if isinstance(rules_data, list):
        for r in rules_data:
            if r.get('ruleID') == rule_id:
                rule = r
                break

    if not rule:
        return {'error': f'Rule {rule_id} not found'}

    # Extract pattern
    when = rule.get('when', {})
    pattern = None
    provider = None

    # Check for all known provider types
    provider_types = [
        'builtin.filecontent',
        'go.referenced',
        'nodejs.referenced',
        'java.referenced',
        'csharp.referenced',
    ]

    for provider_type in provider_types:
        if provider_type in when:
            pattern = when[provider_type].get('pattern')
            provider = provider_type
            break

    return {'rule_id': rule_id, 'pattern': pattern, 'provider': provider}


def fix_pattern_detection(failure_info: dict, llm) -> str:
    """
    Use LLM to generate code hint for failing pattern.

    Args:
        failure_info: Dict from analyze_test_failure
        llm: LLM provider

    Returns:
        Generated code hint string
    """
    pattern = failure_info['pattern']
    provider = failure_info['provider']
    rule_id = failure_info['rule_id']

    # Determine language from provider and pattern
    language_hint = ""
    if provider in ['go.referenced', 'builtin.filecontent']:
        # Check if pattern looks like Go
        if any(
            go_indicator in str(pattern)
            for go_indicator in [
                'net.',
                'net/',
                'golang.org',
                'interface{}',
                '//+build',
                'syscall.',
            ]
        ):
            language_hint = "Go"
    elif provider == 'nodejs.referenced':
        language_hint = "TypeScript/JavaScript"
    elif provider == 'java.referenced':
        language_hint = "Java"
    elif provider == 'csharp.referenced':
        language_hint = "C#"

    prompt = f"""Generate a single-line code snippet that matches this
Konveyor analyzer rule pattern.

Rule ID: {rule_id}
Provider: {provider}
Pattern: {pattern}
Language: {language_hint or "detect from pattern"}

Requirements:
1. MUST be a SINGLE line of code (no newlines)
2. MUST match the pattern exactly
3. Use realistic syntax for the detected language
4. Keep it minimal and simple

Return ONLY the code snippet, nothing else. No markdown, no explanations.

Example formats by language:
- Go: var ip net.IP = net.ParseIP("192.168.1.1")
- Go build constraint: //+build linux darwin
- TypeScript: setTimeout(() => {{ setCount(c => c + 1); setFlag(f => !f); }}, 1000);
- TypeScript: render(<App />, container, () => {{ console.log('rendered'); }});
- TypeScript: interface ButtonProps {{ onClick: () => void; disabled?: boolean; }}
"""

    result = llm.generate(prompt)
    code_hint = result.get('response', '').strip()

    # Clean up markdown formatting
    code_hint = re.sub(r'^```\w*\n?', '', code_hint)
    code_hint = re.sub(r'\n?```$', '', code_hint)
    code_hint = code_hint.strip()

    # Remove newlines if present
    code_hint = code_hint.replace('\n', ' ')

    return code_hint


def main():
    parser = argparse.ArgumentParser(
        description='Generate test data for Konveyor analyzer rules using AI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate Java test data for Spring Boot 4.0 rules
  python scripts/generate_test_data.py \\
    --rules examples/output/spring-boot - 4.0/migration-rules.yaml \\
    --output submission/tests/data/mongodb \\
    --source spring-boot - 3.5 \\
    --target spring-boot - 4.0 \\
    --guide-url \\
      "https://github.com/spring-projects/spring-boot/wiki/Spring-Boot - 4.0-Migration-Guide"

  # Generate TypeScript test data for a directory of rules
  python scripts/generate_test_data.py \\
    --rules /path/to/rulesets/patternfly \\
    --output /path/to/rulesets/patternfly/tests \\
    --source patternfly-v5 \\
    --target patternfly-v6 \\
    --language typescript \\
    --guide-url "https://www.patternfly.org/get-started/upgrade/"
        """,
    )

    parser.add_argument(
        '--rules', required=True, help='Path to rule YAML file or directory containing rule files'
    )
    parser.add_argument('--output', required=True, help='Output directory for test data')
    parser.add_argument('--source', required=True, help='Source framework/version')
    parser.add_argument('--target', required=True, help='Target framework/version')
    parser.add_argument('--guide-url', required=True, help='URL to migration guide')
    parser.add_argument(
        '--language',
        choices=['java', 'typescript', 'go', 'python'],
        help='Programming language (auto-detected if not specified)',
    )
    parser.add_argument(
        '--provider',
        default='anthropic',
        choices=['openai', 'anthropic', 'google'],
        help='LLM provider (default: anthropic)',
    )
    parser.add_argument('--model', help='Model name (uses provider default if not specified)')
    parser.add_argument('--api-key', help='API key (uses environment variable if not specified)')
    parser.add_argument(
        '--delay',
        type=float,
        default=config.TEST_GENERATION_DELAY,
        help=(
            'Delay in seconds between API calls to avoid rate limits '
            f'(default: {config.TEST_GENERATION_DELAY})'
        ),
    )
    parser.add_argument(
        '--max-retries',
        type=int,
        default=config.MAX_RETRY_ATTEMPTS,
        help=(
            'Maximum number of retries for rate limit errors '
            f'(default: {config.MAX_RETRY_ATTEMPTS})'
        ),
    )
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        help='Skip rule files that already have generated test data',
    )
    parser.add_argument(
        '--max-iterations',
        type=int,
        default=0,
        help='Run test-fix loop: generate, test, fix failures, repeat (0=disable, default: 0)',
    )

    args = parser.parse_args()

    # Validate framework names
    try:
        args.source = validate_framework_name(args.source)
        args.target = validate_framework_name(args.target)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Validate inputs
    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"Error: Path not found: {rules_path}", file=sys.stderr)
        return 1

    # Determine if input is a file or directory
    if rules_path.is_file():
        # Single file mode
        rule_files = [rules_path]
    elif rules_path.is_dir():
        # Directory mode - find all YAML files except ruleset.yaml
        rule_files = sorted(
            [
                f
                for f in rules_path.glob('*.yaml')
                if f.name != 'ruleset.yaml' and not f.name.endswith('.test.yaml')
            ]
        )
        if not rule_files:
            print(f"Error: No rule YAML files found in {rules_path}", file=sys.stderr)
            return 1
    else:
        print(f"Error: {rules_path} is neither a file nor directory", file=sys.stderr)
        return 1

    print(f"Found {len(rule_files)} rule file(s) to process")

    # Initialize LLM once
    print(f"\nInitializing {args.provider} LLM...")
    llm = get_llm_provider(args.provider, args.model, args.api_key)
    print(f"  ✓ Using model: {llm.model if hasattr(llm, 'model') else llm.model_name}")

    # Setup output directory structure
    # Validate output path for security (check for path traversal attacks)
    if not is_safe_path(args.output):
        print(f"Error: Output path '{args.output}' contains suspicious patterns", file=sys.stderr)
        return 1

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir = output_dir / 'data'
    data_dir.mkdir(exist_ok=True)

    # Process each rule file
    total_files = len(rule_files)
    skipped_count = 0
    for idx, rule_file in enumerate(rule_files, 1):
        print(f"\n{'=' * 70}")
        print(f"Processing {idx}/{total_files}: {rule_file.name}")
        print(f"{'=' * 70}")

        # Check if test already exists
        test_file_name = rule_file.stem + '.test.yaml'
        test_file_path = output_dir / test_file_name
        if args.skip_existing and test_file_path.exists():
            print("  ⊘ Skipping (test already exists)")
            skipped_count += 1
            continue

        # Load rules from file
        try:
            with open(rule_file, 'r') as f:
                content = yaml.safe_load(f)

            # Validate structure
            if not isinstance(content, (list, dict)):
                print(f"  ⚠ Error: Invalid YAML structure in {rule_file}: expected list or dict")
                skipped_count += 1
                continue

            if isinstance(content, list):
                rules = content
            else:
                rules = [content]

            # Validate that rules have required fields
            if not rules or not all(isinstance(r, dict) for r in rules):
                print(f"  ⚠ Error: Invalid rule structure in {rule_file}")
                skipped_count += 1
                continue

        except yaml.YAMLError as e:
            print(f"  ⚠ Error: YAML parsing error in {rule_file}: {e}")
            skipped_count += 1
            continue
        except (IOError, OSError) as e:
            print(f"  ⚠ Error reading {rule_file}: {e}")
            skipped_count += 1
            continue

        print(f"  ✓ Loaded {len(rules)} rule(s)")

        # Detect or use specified language
        language = args.language or detect_language(rules)
        print(f"  ✓ Language: {language}")

        lang_config = get_language_config(language)

        # Generate data directory name from rule file
        # e.g., "patternfly-v5-to-patternfly-v6-button.yaml" -> "button"
        # Sanitize to avoid analyzer's default exclude patterns (build, target, etc.)
        data_dir_name = sanitize_dir_name(
            rule_file.stem.replace(f'{args.source}-to-{args.target}-', '')
        )

        # Build prompt
        print("  Generating test data with AI...")
        prompt = build_test_generation_prompt(
            rules, args.source, args.target, args.guide_url, language
        )

        # Debug: Save prompt to file for inspection (only if debug environment variable is set)
        if os.environ.get('DEBUG_PROMPTS'):
            debug_dir = output_dir / 'debug'
            debug_dir.mkdir(exist_ok=True)
            debug_prompt_file = debug_dir / f'{data_dir_name}_prompt.txt'
            with open(debug_prompt_file, 'w') as f:
                f.write(prompt)
            print(f"    📝 Debug: Saved prompt to {debug_prompt_file}")

        # Generate with LLM (with retry logic for rate limits)
        response = None
        for retry in range(args.max_retries):
            try:
                result = llm.generate(prompt)
                response = result.get('response', '')

                # Show token usage if available
                if 'usage' in result:
                    usage = result['usage']
                    if 'input_tokens' in usage:
                        print(
                            f"    Input tokens: {usage['input_tokens']}, "
                            f"Output tokens: {usage['output_tokens']}"
                        )
                    elif 'prompt_tokens' in usage:
                        print(
                            f"    Prompt tokens: {usage['prompt_tokens']}, "
                            f"Completion tokens: {usage['completion_tokens']}"
                        )
                break  # Success, exit retry loop

            except Exception as e:
                error_str = str(e)
                if 'rate_limit' in error_str.lower() or '429' in error_str:
                    if retry < args.max_retries - 1:
                        wait_time = 60 * (retry + 1)  # Exponential backoff: 60s, 120s, 180s
                        print(
                            f"  ⚠ Rate limit hit, waiting {wait_time}s before retry "
                            f"{retry + 2}/{args.max_retries}..."
                        )
                        time.sleep(wait_time)
                    else:
                        print(
                            f"  ✗ Rate limit exceeded after {args.max_retries} retries",
                            file=sys.stderr,
                        )
                        response = None
                        break
                else:
                    print(f"  ✗ Error generating test data: {e}", file=sys.stderr)
                    import traceback

                    traceback.print_exc()
                    response = None
                    break

        if not response:
            continue  # Skip to next file

        # Extract code blocks
        code = extract_code_blocks(response, language)

        if not code['build_file'] or not code['source_file']:
            print("  ✗ Could not extract required files from response", file=sys.stderr)
            print(
                f"    Debug: build_file={bool(code['build_file'])}, "
                f"source_file={bool(code['source_file'])}",
                file=sys.stderr,
            )
            if os.environ.get('DEBUG_EXTRACTION'):
                print(f"    Response preview: {response[:500]}...", file=sys.stderr)
            continue  # Skip to next file

        # Validate generated code is in the correct language
        is_valid, error_msg = validate_generated_language(code, language)
        if not is_valid:
            print(f"  ✗ {error_msg}", file=sys.stderr)
            continue  # Skip to next file

        # Create test data directory
        test_data_dir = data_dir / data_dir_name
        src_dir = create_directory_structure(test_data_dir, language)

        # Write build file
        build_file_path = test_data_dir / lang_config['build_file']
        with open(build_file_path, 'w') as f:
            f.write(code['build_file'])
        print(f"  ✓ {build_file_path.relative_to(output_dir)}")

        # Determine appropriate filename based on filePattern requirements
        main_filename = determine_filename_from_filepattern(
            rules, lang_config['main_file'], language
        )

        # Write source file
        source_file_path = src_dir / main_filename
        source_content = code['source_file']

        # Post-process Java files to inject missing imports
        if language == 'java':
            # Extract patterns from rules to get import requirements
            patterns_to_test = extract_patterns_from_rules(rules, language)
            original_content = source_content
            source_content = inject_missing_java_imports(source_content, patterns_to_test, rules)
            if source_content != original_content:
                print("  → Auto-injected missing import statements for IMPORT location rules")

        with open(source_file_path, 'w') as f:
            f.write(source_content)
        print(f"  ✓ {source_file_path.relative_to(output_dir)}")

        # Write config file if present (for Java/Spring Boot projects)
        if code['config_file'] and language == 'java':
            config_filename = code['config_file'].get(
                'filename', f"application.{code['config_file']['type']}"
            )

            # Determine the correct directory based on the filename
            if 'spring.factories' in config_filename:
                # spring.factories goes in META-INF/
                config_dir = test_data_dir / 'src' / 'main' / 'resources' / 'META-INF'
            else:
                # Other config files go in resources/
                config_dir = test_data_dir / 'src' / 'main' / 'resources'

            config_dir.mkdir(parents=True, exist_ok=True)
            config_file_path = config_dir / config_filename

            with open(config_file_path, 'w') as f:
                f.write(code['config_file']['content'])
            print(f"  ✓ {config_file_path.relative_to(output_dir)}")

        # Create any missing config files that the LLM didn't generate
        missing_configs = create_missing_config_files(
            rules, test_data_dir, language, code.get('config_file')
        )
        for config_path in missing_configs:
            print(f"  ✓ {config_path.relative_to(output_dir)} (auto-created)")

        # Create files for file-based patterns (e.g., banner.png)
        file_patterns = create_file_based_patterns(rules, test_data_dir, language)
        for file_path in file_patterns:
            print(f"  ✓ {file_path.relative_to(output_dir)} (pattern file)")

        # Generate test YAML file
        test_yaml_path = generate_test_yaml(rule_file, data_dir_name, rules, output_dir)
        print(f"  ✓ {test_yaml_path.relative_to(output_dir)}")

        # Add delay between API calls (except for the last file)
        if idx < total_files and args.delay > 0:
            print(f"  Waiting {args.delay}s before next file...")
            time.sleep(args.delay)

    print(f"\n{'=' * 70}")
    generated_count = total_files - skipped_count
    print(f"✓ Processed {total_files} rule file(s)")
    if skipped_count > 0:
        print(f"  - Generated: {generated_count}")
        print(f"  - Skipped: {skipped_count}")
    print(f"\nOutput directory: {output_dir}")
    print(f"  - Test YAML files: {len(list(output_dir.glob('*.test.yaml')))} files")
    if data_dir.exists():
        print(f"  - Test data directories: {len(list(data_dir.iterdir()))} directories")
    print("\nNext steps:")
    print(f"  1. Review generated files in: {output_dir}")
    print(f"  2. Run tests: kantra test {output_dir}/*.test.yaml")

    # Test-fix loop if enabled
    if args.max_iterations > 0:
        print(f"\n{'=' * 70}")
        print(f"TEST-FIX LOOP ENABLED (max {args.max_iterations} iterations)")
        print(f"{'=' * 70}")

        for iteration in range(1, args.max_iterations + 1):
            print(f"\n{'=' * 70}")
            print(f"ITERATION {iteration}/{args.max_iterations}")
            print(f"{'=' * 70}")

            # Run tests
            test_results = run_kantra_tests(output_dir)

            if test_results['exit_code'] == 0:
                print(f"\n{'=' * 70}")
                print(f"🎉 SUCCESS! All {test_results['total']} tests passing!")
                print(f"{'=' * 70}")
                return 0

            print(f"\nTests: {test_results['passed']}/{test_results['total']} passing")
            print(f"Failures: {len(test_results['failures'])}")

            if not test_results['failures']:
                print("⚠ No specific failures detected. Check test output above.")
                break

            # Analyze and fix each failure
            fixed_patterns = {}
            for failure in test_results['failures']:
                rule_id = failure['rule_id']
                debug_path = failure['debug_path']

                print(f"\n--- Analyzing {rule_id} ---")

                analysis = analyze_test_failure(debug_path)
                if 'error' in analysis:
                    print(f"  ✗ {analysis['error']}")
                    continue

                print(f"  Pattern: {analysis['pattern']}")
                print(f"  Provider: {analysis['provider']}")

                # Generate fixed code hint
                print("  Generating code hint...")
                code_hint = fix_pattern_detection(analysis, llm)
                print(f"  Code hint: {code_hint}")

                # Store for regeneration
                fixed_patterns[rule_id] = {
                    'pattern': analysis['pattern'],
                    'code_hint': code_hint,
                    'provider': analysis['provider'],
                }

            # Find which rule files need regeneration
            rules_to_regen = set()
            for rule_id in fixed_patterns.keys():
                # Find which rule file contains this rule ID
                for rule_file in rule_files:
                    with open(rule_file) as f:
                        if rule_id in f.read():
                            rules_to_regen.add(rule_file)
                            break

            if not rules_to_regen:
                print("\n⚠ Could not find rule files to regenerate")
                break

            print(f"\nRegenerating {len(rules_to_regen)} rule file(s)...")

            # Temporarily update generate_code_hint_from_pattern by injecting hints
            # Store original function
            global generate_code_hint_from_pattern
            original_func = generate_code_hint_from_pattern

            # Create wrapper that uses our fixed patterns
            def patched_generate_code_hint(pattern, language, description='', message=''):
                # Check if we have a fix for this pattern
                for fix_info in fixed_patterns.values():
                    if fix_info['pattern'] == pattern:
                        return fix_info['code_hint']
                # Fall back to original
                return original_func(pattern, language, description, message)

            # Patch the function
            generate_code_hint_from_pattern = patched_generate_code_hint

            # Regenerate failed tests
            for rule_file in rules_to_regen:
                data_dir_name = sanitize_dir_name(
                    rule_file.stem.replace(f'{args.source}-to-{args.target}-', '')
                )
                test_data_dir = data_dir / data_dir_name

                # Remove old test data
                if test_data_dir.exists():
                    shutil.rmtree(test_data_dir)

                print(f"  Regenerating: {rule_file.name}")

                # Load and regenerate
                try:
                    with open(rule_file, 'r') as f:
                        content = yaml.safe_load(f)

                    # Validate structure
                    if not isinstance(content, (list, dict)):
                        print(f"  ⚠ Error: Invalid YAML structure in {rule_file}, skipping")
                        continue

                    rules = content if isinstance(content, list) else [content]

                    # Validate that rules have required fields
                    if not rules or not all(isinstance(r, dict) for r in rules):
                        print(f"  ⚠ Error: Invalid rule structure in {rule_file}, skipping")
                        continue

                except yaml.YAMLError as e:
                    print(f"  ⚠ Error: YAML parsing error in {rule_file}: {e}, skipping")
                    continue
                except (IOError, OSError) as e:
                    print(f"  ⚠ Error reading {rule_file}: {e}, skipping")
                    continue

                language = args.language or detect_language(rules)
                lang_config = get_language_config(language)
                prompt = build_test_generation_prompt(
                    rules, args.source, args.target, args.guide_url, language
                )

                # Debug: Save prompt to file for inspection
                if args.max_iterations > 0:  # Only on first iteration
                    test_data_dir.mkdir(parents=True, exist_ok=True)
                    debug_prompt_file = test_data_dir / 'debug_prompt.txt'
                    with open(debug_prompt_file, 'w') as f:
                        f.write(prompt)
                    print(
                        f"    📝 Debug: Saved prompt to {debug_prompt_file.relative_to(output_dir)}"
                    )

                # Generate with LLM
                result = llm.generate(prompt)
                response = result.get('response', '')

                # Extract and write files
                code = extract_code_blocks(response, language)
                if code['build_file'] and code['source_file']:
                    # Validate generated code is in the correct language
                    is_valid, error_msg = validate_generated_language(code, language)
                    if not is_valid:
                        print(f"    ✗ {error_msg}", file=sys.stderr)
                        print(
                            "    ↻ Regenerating with stronger language constraints...",
                            file=sys.stderr,
                        )
                        continue  # Will retry in next iteration

                    src_dir = create_directory_structure(test_data_dir, language)

                    # Write build file
                    with open(test_data_dir / lang_config['build_file'], 'w') as f:
                        f.write(code['build_file'])

                    # Write source file
                    with open(src_dir / lang_config['main_file'], 'w') as f:
                        f.write(code['source_file'])

                    # Write config file if present
                    if code['config_file'] and language == 'java':
                        config_filename = code['config_file'].get(
                            'filename', f"application.{code['config_file']['type']}"
                        )
                        if 'spring.factories' in config_filename:
                            config_dir = test_data_dir / 'src' / 'main' / 'resources' / 'META-INF'
                        else:
                            config_dir = test_data_dir / 'src' / 'main' / 'resources'
                        config_dir.mkdir(parents=True, exist_ok=True)
                        with open(config_dir / config_filename, 'w') as f:
                            f.write(code['config_file']['content'])

                    # Create any missing config files
                    missing_configs = create_missing_config_files(
                        rules, test_data_dir, language, code.get('config_file')
                    )

                    # Create files for file-based patterns
                    file_patterns = create_file_based_patterns(rules, test_data_dir, language)

                    print("    ✓ Regenerated test data")
                else:
                    print("    ✗ Could not extract code")

            # Restore original function
            generate_code_hint_from_pattern = original_func

            print(f"\n  Waiting {args.delay}s before next iteration...")
            time.sleep(args.delay)

        # Max iterations reached
        print(f"\n{'=' * 70}")
        print(f"⚠ Maximum iterations ({args.max_iterations}) reached")
        final_results = run_kantra_tests(output_dir)
        print(f"Final: {final_results['passed']}/{final_results['total']} tests passing")
        print(f"{'=' * 70}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
