"""
ESLint Rule Extraction Module

Extracts Konveyor analyzer rules from ESLint codemod repositories (e.g., PatternFly pf-codemods).

This module parses TypeScript ESLint rule definitions and converts them into MigrationPattern
objects that can be used to generate Konveyor analyzer rules. It handles:

- Simple prop renames (e.g., isActive -> isClicked)
- Prop removals (e.g., isSelectableRaised removed)
- Component deprecations (e.g., Chip deprecated, use Label)
- Import path changes

Architecture:
    1. Clone or read ESLint rule repository
    2. Parse TypeScript rule files using regex patterns
    3. Extract metadata (component names, prop changes, messages)
    4. Read example files (*Input.tsx, *Output.tsx, *.md)
    5. Generate MigrationPattern objects
    6. Feed into existing rule generation pipeline

Usage:
    >>> extractor = ESLintRuleExtractor("https://github.com/patternfly/pf-codemods.git")
    >>> patterns = extractor.extract_patterns(
    ...     rules_path="packages/eslint-plugin-pf-codemods/src/rules/v6",
    ...     source_framework="patternfly-v5",
    ...     target_framework="patternfly-v6"
    ... )
    >>> # patterns can now be passed to AnalyzerRuleGenerator

Supported Rule Types:
    - renameProps: Simple prop renames (HIGH PRIORITY - ~40% of rules)
    - removeProps: Prop removals (HIGH PRIORITY - ~20% of rules)
    - deprecateComponent: Component deprecations (HIGH PRIORITY - ~8% of rules)
    - replaceImport: Import path changes (MEDIUM PRIORITY - ~4% of rules)

Unsupported (Too Complex):
    - Rules requiring AST traversal (parent/child navigation)
    - Rules with conditional logic based on prop values
    - Rules with complex restructuring
    - See issue #25 for complete analysis
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from .logging_setup import get_logger
from .schema import MigrationPattern

# Get module logger
logger = get_logger(__name__)


class ESLintRuleMetadata:
    """Metadata extracted from an ESLint rule."""

    def __init__(
        self,
        rule_name: str,
        rule_type: str,
        component_name: Optional[str] = None,
        prop_renames: Optional[Dict[str, str]] = None,
        prop_removals: Optional[List[str]] = None,
        messages: Optional[Dict[str, str]] = None,
        package_name: Optional[str] = None,
        example_before: Optional[str] = None,
        example_after: Optional[str] = None,
        documentation_url: Optional[str] = None,
    ):
        """
        Initialize ESLint rule metadata.

        Args:
            rule_name: Name of the rule (e.g., "button-rename-isActive")
            rule_type: Type of rule ("rename", "removal", "deprecation", "import", "unknown")
            component_name: React component name (e.g., "Button")
            prop_renames: Dict mapping old prop names to new prop names
            prop_removals: List of removed prop names
            messages: Dict mapping prop names to custom messages
            package_name: Package name (e.g., "@patternfly/react-core")
            example_before: Code example before migration
            example_after: Code example after migration
            documentation_url: Link to PR or documentation
        """
        self.rule_name = rule_name
        self.rule_type = rule_type
        self.component_name = component_name
        self.prop_renames = prop_renames or {}
        self.prop_removals = prop_removals or []
        self.messages = messages or {}
        self.package_name = package_name or "@patternfly/react-core"
        self.example_before = example_before
        self.example_after = example_after
        self.documentation_url = documentation_url


class ESLintRuleExtractor:
    """Extract Konveyor patterns from ESLint codemod rules."""

    def __init__(self, repo_url: Optional[str] = None, local_path: Optional[str] = None):
        """
        Initialize ESLint rule extractor.

        Args:
            repo_url: Git repository URL (e.g., "https://github.com/patternfly/pf-codemods.git")
            local_path: Path to local repository (alternative to repo_url)
        """
        self.repo_url = repo_url
        self.local_path = local_path
        self._temp_dir = None

    def extract_patterns(
        self,
        rules_path: str = "packages/eslint-plugin-pf-codemods/src/rules/v6",
        source_framework: str = "patternfly-v5",
        target_framework: str = "patternfly-v6",
        rule_filter: Optional[List[str]] = None,
    ) -> List[MigrationPattern]:
        """
        Extract migration patterns from ESLint rules.

        Args:
            rules_path: Path to rules directory within repository
            source_framework: Source framework name
            target_framework: Target framework name
            rule_filter: Optional list of rule names to extract (e.g., ["button-rename-isActive"])

        Returns:
            List of MigrationPattern objects
        """
        # Get repository path (clone if needed)
        repo_path = self._get_repo_path()

        # Find all rule directories
        rules_dir = Path(repo_path) / rules_path
        if not rules_dir.exists():
            logger.error(f"Rules directory not found: {rules_dir}")
            return []

        logger.info(f"Scanning ESLint rules in: {rules_dir}")

        # Find all rule subdirectories (each rule has its own directory)
        rule_dirs = [d for d in rules_dir.iterdir() if d.is_dir()]
        logger.info(f"Found {len(rule_dirs)} rule directories")

        # Extract patterns from each rule
        all_patterns = []
        for rule_dir in rule_dirs:
            rule_name = rule_dir.name

            # Apply filter if specified
            if rule_filter and rule_name not in rule_filter:
                continue

            logger.info(f"Processing rule: {rule_name}")

            try:
                # Parse the rule
                metadata = self._parse_rule_directory(rule_dir)

                if metadata is None:
                    logger.warning(f"Could not parse rule: {rule_name}")
                    continue

                # Convert to MigrationPattern objects
                patterns = self._metadata_to_patterns(metadata, source_framework, target_framework)

                if patterns:
                    logger.info(f"  → Extracted {len(patterns)} patterns from {rule_name}")
                    all_patterns.extend(patterns)
                else:
                    logger.warning(f"  → No patterns extracted from {rule_name}")

            except Exception as e:
                logger.warning(f"Error processing rule {rule_name}: {e}")
                continue

        logger.info(f"Total patterns extracted: {len(all_patterns)}")
        return all_patterns

    def _camel_to_kebab(self, name: str) -> str:
        """
        Convert camelCase to kebab-case.

        Args:
            name: camelCase string

        Returns:
            kebab-case string

        Examples:
            >>> _camel_to_kebab("buttonRenameIsActive")
            "button-rename-is-active"
        """
        # Insert hyphen before uppercase letters and convert to lowercase
        result = re.sub(r'(?<!^)(?=[A-Z])', '-', name).lower()
        return result

    def _get_repo_path(self) -> Path:
        """Get path to repository (clone if needed)."""
        if self.local_path:
            path = Path(self.local_path)
            if not path.exists():
                raise ValueError(f"Local repository path does not exist: {self.local_path}")
            return path

        if self.repo_url:
            # Clone to temporary directory
            self._temp_dir = tempfile.mkdtemp(prefix="eslint-rules-")
            clone_path = Path(self._temp_dir) / "repo"

            logger.info(f"Cloning repository: {self.repo_url}")
            logger.info(f"Clone destination: {clone_path}")

            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", self.repo_url, str(clone_path)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                logger.info("Repository cloned successfully")
                return clone_path
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone repository: {e.stderr}")
                raise

        raise ValueError("Either repo_url or local_path must be provided")

    def _parse_rule_directory(self, rule_dir: Path) -> Optional[ESLintRuleMetadata]:
        """
        Parse an ESLint rule directory.

        Args:
            rule_dir: Path to rule directory

        Returns:
            ESLintRuleMetadata or None if parsing fails
        """
        rule_name = rule_dir.name

        # Convert camelCase directory name to kebab-case for file lookup
        # e.g., buttonRenameIsActive -> button-rename-isActive
        kebab_name = self._camel_to_kebab(rule_name)

        # Find the main TypeScript file
        # Try kebab-case first (most common pattern)
        ts_file = rule_dir / f"{kebab_name}.ts"
        if not ts_file.exists():
            # Fall back to finding any non-test .ts file
            ts_files = list(rule_dir.glob("*.ts"))
            ts_files = [f for f in ts_files if not f.name.endswith(".test.ts")]

            if not ts_files:
                logger.warning(f"No TypeScript file found in {rule_dir}")
                return None

            ts_file = ts_files[0]

        # Read TypeScript content
        try:
            with open(ts_file, "r", encoding="utf-8") as f:
                ts_content = f.read()
        except Exception as e:
            logger.error(f"Failed to read {ts_file}: {e}")
            return None

        # Detect rule type and extract metadata
        metadata = self._parse_typescript_content(rule_name, ts_content)

        if metadata is None:
            return None

        # Read example files if they exist
        # Try both camelCase (directory name) and kebab-case for example files
        input_file = rule_dir / f"{rule_name}Input.tsx"
        if not input_file.exists():
            input_file = rule_dir / f"{kebab_name}Input.tsx"

        output_file = rule_dir / f"{rule_name}Output.tsx"
        if not output_file.exists():
            output_file = rule_dir / f"{kebab_name}Output.tsx"

        md_file = rule_dir / f"{kebab_name}.md"
        if not md_file.exists():
            md_file = rule_dir / f"{rule_name}.md"

        if input_file.exists():
            try:
                with open(input_file, "r", encoding="utf-8") as f:
                    metadata.example_before = f.read()
            except Exception as e:
                logger.warning(f"Failed to read {input_file}: {e}")

        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    metadata.example_after = f.read()
            except Exception as e:
                logger.warning(f"Failed to read {output_file}: {e}")

        if md_file.exists():
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    md_content = f.read()
                    # Try to extract PR link from markdown
                    pr_match = re.search(r'https://github\.com/[^/]+/[^/]+/pull/\d+', md_content)
                    if pr_match:
                        metadata.documentation_url = pr_match.group(0)
            except Exception as e:
                logger.warning(f"Failed to read {md_file}: {e}")

        return metadata

    def _parse_typescript_content(
        self, rule_name: str, ts_content: str
    ) -> Optional[ESLintRuleMetadata]:
        """
        Parse TypeScript content to extract rule metadata.

        Args:
            rule_name: Name of the rule
            ts_content: TypeScript file content

        Returns:
            ESLintRuleMetadata or None if parsing fails
        """
        # Detect rule type based on helper functions used
        if "renameProps(" in ts_content:
            return self._parse_rename_props(rule_name, ts_content)
        elif "removeProps(" in ts_content:
            return self._parse_remove_props(rule_name, ts_content)
        elif "moveSpecifiers(" in ts_content:
            return self._parse_move_specifiers(rule_name, ts_content)
        elif "renameComponent(" in ts_content:
            return self._parse_rename_component(rule_name, ts_content)
        elif "renameInterface(" in ts_content:
            return self._parse_rename_interface(rule_name, ts_content)
        elif "deprecateComponent(" in ts_content or "deprecated" in ts_content.lower():
            return self._parse_deprecation(rule_name, ts_content)
        elif "create: function" in ts_content:
            # Try to extract warn-only pattern as fallback
            return self._parse_warn_only(rule_name, ts_content)
        else:
            # Unknown or complex rule type
            logger.warning(f"Unknown rule type for {rule_name}")
            return None

    def _parse_rename_props(self, rule_name: str, ts_content: str) -> Optional[ESLintRuleMetadata]:
        """Parse a renameProps() ESLint rule."""
        # Try to extract component name and prop renames
        # Pattern: renameProps({ ComponentName: { oldProp: "newProp" } })

        # Find the renameProps call
        rename_match = re.search(r'renameProps\s*\(\s*\{([^}]+)\}', ts_content, re.DOTALL)
        if not rename_match:
            logger.warning(f"Could not find renameProps pattern in {rule_name}")
            return None

        rename_block = rename_match.group(1)

        # Extract component name (first identifier before colon)
        component_match = re.search(r'(\w+)\s*:\s*\{', rename_block)
        if not component_match:
            logger.warning(f"Could not extract component name from {rule_name}")
            return None

        component_name = component_match.group(1)

        # Extract prop renames and removals
        # Pattern: oldProp: "newProp" or oldProp: { newName: "newProp", message: "..." }
        prop_renames = {}
        prop_removals = []
        messages = {}

        # First, handle complex pattern: oldProp: { newName: "newProp", message: "..." }
        # This regex captures the message field which can span multiple lines
        complex_matches = []
        for match in re.finditer(
            r'(\w+)\s*:\s*\{\s*newName\s*:\s*"([^"]*)"',
            rename_block,
            re.DOTALL,
        ):
            old_prop = match.group(1)
            new_prop = match.group(2)
            complex_matches.append(old_prop)

            # Try to extract message if present (it's on a separate line often)
            # Look for message: "..." or message: '...' after this prop
            prop_section_start = match.end()
            # Find the next closing brace (end of this prop definition)
            prop_section_end = rename_block.find('}', prop_section_start)
            if prop_section_end != -1:
                prop_section = rename_block[prop_section_start:prop_section_end]
                message_match = re.search(
                    r'message\s*:\s*["\']([^"\']+)["\']', prop_section, re.DOTALL
                )
                if message_match:
                    messages[old_prop] = message_match.group(1).strip()

            if new_prop:  # Rename
                prop_renames[old_prop] = new_prop
            else:  # Removal (empty newName)
                prop_removals.append(old_prop)

        # Then handle simple pattern: oldProp: "newProp" (but skip if already handled by complex)
        for match in re.finditer(r'(\w+)\s*:\s*"([^"]+)"', rename_block):
            old_prop = match.group(1)
            # Skip if this was already processed as complex pattern
            # Skip special keys like 'newName', 'message'
            if old_prop in complex_matches or old_prop in ['newName', 'message']:
                continue

            new_prop = match.group(2)
            if new_prop:  # Not empty
                prop_renames[old_prop] = new_prop
            else:
                prop_removals.append(old_prop)

        # If we have removals, return as removal type
        if prop_removals and not prop_renames:
            return ESLintRuleMetadata(
                rule_name=rule_name,
                rule_type="removal",
                component_name=component_name,
                prop_removals=prop_removals,
                messages=messages,
            )
        # If we have only renames, return as rename type
        elif prop_renames and not prop_removals:
            return ESLintRuleMetadata(
                rule_name=rule_name,
                rule_type="rename",
                component_name=component_name,
                prop_renames=prop_renames,
                messages=messages,
            )
        # If we have both, create two separate metadata objects
        # For now, prioritize renames and log a warning
        elif prop_renames and prop_removals:
            logger.warning(
                f"Rule {rule_name} has both renames and removals, only extracting renames"
            )
            return ESLintRuleMetadata(
                rule_name=rule_name,
                rule_type="rename",
                component_name=component_name,
                prop_renames=prop_renames,
                messages=messages,
            )
        else:
            logger.warning(f"No prop renames or removals found in {rule_name}")
            return None

    def _parse_remove_props(self, rule_name: str, ts_content: str) -> Optional[ESLintRuleMetadata]:
        """Parse a removeProps() ESLint rule."""
        # Similar to renameProps but for removals
        # Pattern: removeProps({ ComponentName: ["prop1", "prop2"] })
        # or renameProps({ ComponentName: { prop: "" } }) for removals via rename

        # Try removeProps first
        remove_match = re.search(r'removeProps\s*\(\s*\{([^}]+)\}', ts_content, re.DOTALL)
        if remove_match:
            remove_block = remove_match.group(1)

            # Extract component name
            component_match = re.search(r'(\w+)\s*:\s*\[', remove_block)
            if not component_match:
                return None

            component_name = component_match.group(1)

            # Extract removed props (array of strings)
            prop_removals = []
            for match in re.finditer(r'"(\w+)"', remove_block):
                prop_removals.append(match.group(1))

            if not prop_removals:
                return None

            return ESLintRuleMetadata(
                rule_name=rule_name,
                rule_type="removal",
                component_name=component_name,
                prop_removals=prop_removals,
            )

        # Try renameProps with empty string (indicates removal)
        rename_match = re.search(r'renameProps\s*\(\s*\{([^}]+)\}', ts_content, re.DOTALL)
        if rename_match:
            rename_block = rename_match.group(1)

            # Extract component name
            component_match = re.search(r'(\w+)\s*:\s*\{', rename_block)
            if not component_match:
                return None

            component_name = component_match.group(1)

            # Look for props with empty string or removal indicators
            prop_removals = []
            messages = {}

            # Pattern: prop: "" or prop: { newName: "" }
            for match in re.finditer(
                r'(\w+)\s*:\s*(?:""|\{\s*newName\s*:\s*""(?:,\s*message\s*:\s*"([^"]+)")?)',
                rename_block,
            ):
                prop_name = match.group(1)
                message = match.group(2) if match.lastindex >= 2 else None

                prop_removals.append(prop_name)
                if message:
                    messages[prop_name] = message

            if not prop_removals:
                return None

            return ESLintRuleMetadata(
                rule_name=rule_name,
                rule_type="removal",
                component_name=component_name,
                prop_removals=prop_removals,
                messages=messages,
            )

        return None

    def _parse_deprecation(self, rule_name: str, ts_content: str) -> Optional[ESLintRuleMetadata]:
        """Parse a component deprecation rule."""
        # Look for deprecation patterns
        # Try to extract component name and replacement

        # Pattern 1: Simple message about deprecation
        deprecation_match = re.search(
            r'([\w]+)\s+(?:has been deprecated|is deprecated)', ts_content, re.IGNORECASE
        )
        if deprecation_match:
            component_name = deprecation_match.group(1)

            # Try to find replacement component
            replacement_match = re.search(
                r'(?:replaced with|use)\s+([\w]+)', ts_content, re.IGNORECASE
            )
            replacement = replacement_match.group(1) if replacement_match else None

            return ESLintRuleMetadata(
                rule_name=rule_name,
                rule_type="deprecation",
                component_name=component_name,
                messages={"": replacement or "Component deprecated"},
            )

        return None

    def _parse_move_specifiers(
        self, rule_name: str, ts_content: str
    ) -> Optional[ESLintRuleMetadata]:
        """
        Parse a moveSpecifiers() ESLint rule (import path changes).

        Pattern: moveSpecifiers(specifiersToMove, fromPackage, toPackage, message)
        Example: Move DualListSelector from '@patternfly/react-core/next'
                 to '@patternfly/react-core'
        """
        # Extract the array of specifiers to move
        specifiers_match = re.search(r'specifiersToMove\s*=\s*\[([^\]]+)\]', ts_content, re.DOTALL)
        if not specifiers_match:
            logger.warning(f"Could not find specifiersToMove in {rule_name}")
            return None

        specifiers_block = specifiers_match.group(1)

        # Extract component names from the array
        components = re.findall(r'"([^"]+)"', specifiers_block)
        if not components:
            logger.warning(f"No components found in specifiersToMove for {rule_name}")
            return None

        # Extract fromPackage and toPackage
        from_match = re.search(r'fromPackage\s*=\s*"([^"]+)"', ts_content)
        to_match = re.search(r'toPackage\s*=\s*"([^"]+)"', ts_content)

        if not from_match or not to_match:
            logger.warning(f"Could not find fromPackage/toPackage in {rule_name}")
            return None

        from_package = from_match.group(1)
        to_package = to_match.group(1)

        # Extract message if present
        message_match = re.search(r'messageAfterImportNameChange\s*=\s*"([^"]+)"', ts_content)
        message = message_match.group(1) if message_match else None

        # For moveSpecifiers, we'll store the first component as the "main" component
        # and create multiple patterns in _metadata_to_patterns
        return ESLintRuleMetadata(
            rule_name=rule_name,
            rule_type="import",
            component_name=", ".join(components),  # Store all components
            prop_renames={from_package: to_package},  # Reuse prop_renames for packages
            messages={
                "import": message or f"Import path changed from {from_package} to {to_package}"
            },
        )

    def _parse_rename_component(
        self, rule_name: str, ts_content: str
    ) -> Optional[ESLintRuleMetadata]:
        """
        Parse a renameComponent() ESLint rule.

        Pattern: renameComponent({ OldComponent: "NewComponent" })
        Example: MastheadBrand → MastheadLogo
        """
        # Find the renameComponent call
        rename_match = re.search(r'renames\s*=\s*\{([^}]+)\}', ts_content, re.DOTALL)
        if not rename_match:
            # Try alternate pattern
            rename_match = re.search(r'renameComponent\s*\(\s*\{([^}]+)\}', ts_content, re.DOTALL)

        if not rename_match:
            logger.warning(f"Could not find renameComponent pattern in {rule_name}")
            return None

        rename_block = rename_match.group(1)

        # Extract component renames
        component_renames = {}
        for match in re.finditer(r'(\w+)\s*:\s*"([^"]+)"', rename_block):
            old_name = match.group(1)
            new_name = match.group(2)
            component_renames[old_name] = new_name

        if not component_renames:
            logger.warning(f"No component renames found in {rule_name}")
            return None

        # For component renames, use the first rename as primary
        # (we'll create multiple patterns in _metadata_to_patterns if needed)
        first_old = list(component_renames.keys())[0]

        return ESLintRuleMetadata(
            rule_name=rule_name,
            rule_type="component-rename",
            component_name=first_old,
            prop_renames=component_renames,  # Store all renames
        )

    def _parse_rename_interface(
        self, rule_name: str, ts_content: str
    ) -> Optional[ESLintRuleMetadata]:
        """
        Parse a renameInterface() ESLint rule.

        Pattern: renameInterface({ OldInterface: { newName: "NewInterface", message: "..." } })
        Example: FormFiledGroupHeaderTitleTextObject → FormFieldGroupHeaderTitleTextObject
        """
        # Find the renameInterface call
        rename_match = re.search(r'renameInterface\s*\(\s*\{([^}]+)\}', ts_content, re.DOTALL)
        if not rename_match:
            logger.warning(f"Could not find renameInterface pattern in {rule_name}")
            return None

        rename_block = rename_match.group(1)

        # Extract interface name (first identifier before colon)
        interface_match = re.search(r'(\w+)\s*:\s*\{', rename_block)
        if not interface_match:
            logger.warning(f"Could not extract interface name from {rule_name}")
            return None

        old_interface = interface_match.group(1)

        # Extract new name and message
        new_name_match = re.search(r'newName\s*:\s*"([^"]+)"', rename_block)
        message_match = re.search(r'message\s*:\s*"([^"]+)"', rename_block, re.DOTALL)

        if not new_name_match:
            logger.warning(f"Could not extract newName from {rule_name}")
            return None

        new_interface = new_name_match.group(1)
        message = message_match.group(1) if message_match else None

        return ESLintRuleMetadata(
            rule_name=rule_name,
            rule_type="interface-rename",
            component_name=old_interface,
            prop_renames={old_interface: new_interface},
            messages={"interface": message} if message else {},
        )

    def _parse_warn_only(self, rule_name: str, ts_content: str) -> Optional[ESLintRuleMetadata]:
        """
        Parse a warn-only ESLint rule (create: function with context.report).

        These rules detect component usage and provide warnings about markup/API changes
        without automatic fixes.

        Pattern:
            create: function (context) {
                const componentImport = imports.find(...)
                return { JSXOpeningElement(node) {
                    context.report({ message: "Warning..." })
                }}
            }
        """
        # Extract component names from getFromPackage
        # Pattern: getFromPackage(context, "@patternfly/react-core")
        package_match = re.search(r'getFromPackage\([^,]+,\s*["\']([^"\']+)["\']', ts_content)
        if not package_match:
            # Not a standard warn-only pattern
            return None

        package_name = package_match.group(1)

        # Try to extract component name from imports.find()
        # Pattern: imports.find(... imported.name === "ComponentName")
        component_matches = re.findall(r'imported\.name\s*===\s*["\'](\w+)["\']', ts_content)

        # Also check for componentImports.filter pattern (multiple components)
        filter_matches = re.findall(
            r'\[([^\]]+)\]\.includes\(specifier\.imported\.name\)', ts_content, re.DOTALL
        )
        if filter_matches:
            # Extract component names from array like ["Th", "Td"]
            for match in filter_matches:
                additional = re.findall(r'["\'](\w+)["\']', match)
                component_matches.extend(additional)

        if not component_matches:
            # Try alternate pattern: specifier.imported.name === 'ComponentName'
            alt_matches = re.findall(
                r'specifier\.imported\.name\s*===\s*["\'](\w+)["\']', ts_content
            )
            component_matches.extend(alt_matches)

        if not component_matches:
            logger.warning(f"Could not extract component name from warn-only rule {rule_name}")
            return None

        # Extract warning message from context.report()
        # Pattern: message: "The markup for..."
        message_match = re.search(r'message\s*:\s*["\']([^"\']+)["\']', ts_content, re.DOTALL)
        if not message_match:
            # Try multi-line string or template literal
            message_match = re.search(r'message\s*:\s*`([^`]+)`', ts_content, re.DOTALL)

        if not message_match:
            logger.warning(f"Could not extract warning message from {rule_name}")
            return None

        warning_message = message_match.group(1).strip()

        return ESLintRuleMetadata(
            rule_name=rule_name,
            rule_type="warn",
            component_name=", ".join(component_matches),  # Store all components
            package_name=package_name,
            messages={"warn": warning_message},
        )

    def _metadata_to_patterns(
        self, metadata: ESLintRuleMetadata, source_framework: str, target_framework: str
    ) -> List[MigrationPattern]:
        """
        Convert ESLintRuleMetadata to MigrationPattern objects.

        Args:
            metadata: Extracted ESLint rule metadata
            source_framework: Source framework name
            target_framework: Target framework name

        Returns:
            List of MigrationPattern objects
        """
        patterns = []

        if metadata.rule_type == "rename":
            # Create a pattern for each prop rename
            for old_prop, new_prop in metadata.prop_renames.items():
                pattern = self._create_rename_pattern(
                    metadata.component_name,
                    old_prop,
                    new_prop,
                    metadata.messages.get(old_prop),
                    metadata.example_before,
                    metadata.example_after,
                    metadata.documentation_url,
                )
                patterns.append(pattern)

        elif metadata.rule_type == "removal":
            # Create a pattern for each removed prop
            for prop in metadata.prop_removals:
                pattern = self._create_removal_pattern(
                    metadata.component_name,
                    prop,
                    metadata.messages.get(prop),
                    metadata.example_before,
                    metadata.example_after,
                    metadata.documentation_url,
                )
                patterns.append(pattern)

        elif metadata.rule_type == "deprecation":
            # Create a single pattern for component deprecation
            pattern = self._create_deprecation_pattern(
                metadata.component_name,
                metadata.messages.get("", "Component deprecated"),
                metadata.example_before,
                metadata.example_after,
                metadata.documentation_url,
            )
            patterns.append(pattern)

        elif metadata.rule_type == "import":
            # Create patterns for import path changes
            # Extract from_package and to_package from prop_renames
            from_package, to_package = list(metadata.prop_renames.items())[0]
            components = metadata.component_name.split(", ")
            message = metadata.messages.get("import", "")

            for component in components:
                pattern = self._create_import_pattern(
                    component.strip(),
                    from_package,
                    to_package,
                    message,
                    metadata.example_before,
                    metadata.example_after,
                    metadata.documentation_url,
                )
                patterns.append(pattern)

        elif metadata.rule_type == "component-rename":
            # Create patterns for component renames
            for old_component, new_component in metadata.prop_renames.items():
                pattern = self._create_component_rename_pattern(
                    old_component,
                    new_component,
                    metadata.example_before,
                    metadata.example_after,
                    metadata.documentation_url,
                )
                patterns.append(pattern)

        elif metadata.rule_type == "interface-rename":
            # Create pattern for interface rename
            old_interface, new_interface = list(metadata.prop_renames.items())[0]
            message = metadata.messages.get("interface")
            pattern = self._create_interface_rename_pattern(
                old_interface,
                new_interface,
                message,
                metadata.example_before,
                metadata.example_after,
                metadata.documentation_url,
            )
            patterns.append(pattern)

        elif metadata.rule_type == "warn":
            # Create warn-only patterns (one per component)
            components = metadata.component_name.split(", ")
            warning_message = metadata.messages.get("warn", "")

            for component in components:
                pattern = self._create_warn_pattern(
                    component.strip(),
                    warning_message,
                    metadata.example_before,
                    metadata.example_after,
                    metadata.documentation_url,
                )
                patterns.append(pattern)

        return patterns

    def _create_rename_pattern(
        self,
        component: str,
        old_prop: str,
        new_prop: str,
        custom_message: Optional[str],
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for a prop rename."""
        # Use combo rule pattern (nodejs.referenced + builtin.filecontent)
        # This matches the existing PatternFly rule generation strategy

        message = custom_message or f"The {old_prop} prop has been renamed to {new_prop}"

        return MigrationPattern(
            source_pattern=f"{component} {old_prop}",
            target_pattern=f"{component} {new_prop}",
            source_fqn=component,
            complexity="LOW",
            category="api",
            concern="component-props",
            provider_type="combo",
            when_combo={
                "nodejs_pattern": component,
                "builtin_pattern": f"<{component}[^>]*\\\\b{old_prop}\\\\b",
                "file_pattern": "\\.(j|t)sx?$",
            },
            rationale=message,
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def _create_removal_pattern(
        self,
        component: str,
        prop: str,
        custom_message: Optional[str],
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for a prop removal."""
        message = custom_message or f"The {prop} prop has been removed from {component}"

        return MigrationPattern(
            source_pattern=f"{component} {prop}",
            target_pattern=None,  # Removal has no replacement
            source_fqn=component,
            complexity="MEDIUM",
            category="api",
            concern="component-props",
            provider_type="combo",
            when_combo={
                "nodejs_pattern": component,
                "builtin_pattern": f"<{component}[^>]*\\\\b{prop}\\\\b",
                "file_pattern": "\\.(j|t)sx?$",
            },
            rationale=message,
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def _create_deprecation_pattern(
        self,
        component: str,
        replacement: str,
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for a deprecated component."""
        message = f"{component} has been deprecated. {replacement}"

        return MigrationPattern(
            source_pattern=component,
            target_pattern=None,
            source_fqn=component,
            complexity="HIGH",
            category="api",
            concern="component-deprecation",
            provider_type="nodejs",
            rationale=message,
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def _create_import_pattern(
        self,
        component: str,
        from_package: str,
        to_package: str,
        custom_message: Optional[str],
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for import path changes."""
        message = custom_message or f"Import path changed from {from_package} to {to_package}"

        # Use builtin.filecontent to detect the old import path
        return MigrationPattern(
            source_pattern=f"{component} import from {from_package}",
            target_pattern=f"{component} import from {to_package}",
            source_fqn=from_package,
            complexity="TRIVIAL",
            category="api",
            concern="imports",
            provider_type="builtin",
            file_pattern="\\.(j|t)sx?$",
            rationale=f"{component} {message}",
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def _create_component_rename_pattern(
        self,
        old_component: str,
        new_component: str,
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for component renames."""
        message = f"{old_component} has been renamed to {new_component}"

        # Use combo rule to detect both import and usage
        return MigrationPattern(
            source_pattern=old_component,
            target_pattern=new_component,
            source_fqn=old_component,
            complexity="LOW",
            category="api",
            concern="component-renames",
            provider_type="combo",
            when_combo={
                "nodejs_pattern": old_component,
                "builtin_pattern": f"<{old_component}[^>]*>",
                "file_pattern": "\\.(j|t)sx?$",
            },
            rationale=message,
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def _create_interface_rename_pattern(
        self,
        old_interface: str,
        new_interface: str,
        custom_message: Optional[str],
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for TypeScript interface renames."""
        message = custom_message or f"{old_interface} has been renamed to {new_interface}"

        # Use builtin.filecontent to detect TypeScript interface usage
        return MigrationPattern(
            source_pattern=old_interface,
            target_pattern=new_interface,
            source_fqn=old_interface,
            complexity="TRIVIAL",
            category="api",
            concern="typescript-types",
            provider_type="builtin",
            file_pattern="\\.(ts|tsx)$",
            rationale=message,
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def _create_warn_pattern(
        self,
        component: str,
        warning_message: str,
        example_before: Optional[str],
        example_after: Optional[str],
        doc_url: Optional[str],
    ) -> MigrationPattern:
        """Create a MigrationPattern for warn-only rules (markup/API changes)."""
        # Extract short description from warning message (first sentence)
        short_desc = warning_message.split('.')[0] if '.' in warning_message else warning_message
        if len(short_desc) > 80:
            short_desc = short_desc[:77] + "..."

        # Use combo rule to detect component usage
        return MigrationPattern(
            source_pattern=f"{component} (markup/API change)",
            target_pattern=None,  # No automatic replacement
            source_fqn=component,
            complexity="MEDIUM",
            category="potential",
            concern="markup-changes",
            provider_type="combo",
            when_combo={
                "nodejs_pattern": component,
                "builtin_pattern": f"<{component}[^>]*>",
                "file_pattern": "\\.(j|t)sx?$",
            },
            rationale=f"{short_desc}. Manual review required: {warning_message}",
            example_before=example_before,
            example_after=example_after,
            documentation_url=doc_url,
        )

    def cleanup(self):
        """Clean up temporary directory if created."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            import shutil

            shutil.rmtree(self._temp_dir)
            logger.info(f"Cleaned up temporary directory: {self._temp_dir}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()
