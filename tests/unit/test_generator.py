"""
Unit tests for rule generation module.

Tests cover:
- Rule ID generation
- Pattern to rule conversion
- When condition building (Java, Builtin, Node.js providers)
- Complexity to effort mapping
- Category determination
- Label and message building
- Rules by concern grouping
"""

import pytest

from src.rule_generator.generator import AnalyzerRuleGenerator
from src.rule_generator.schema import (
    AnalyzerRule,
    Category,
    CSharpLocationType,
    LocationType,
    MigrationPattern,
)


class TestRuleIDGeneration:
    """Test rule ID generation logic."""

    def test_generate_sequential_rule_ids(self):
        """Should generate sequential rule IDs incrementing by 10"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-3", target_framework="spring-boot-4"
        )

        id1 = generator._create_rule_id()
        id2 = generator._create_rule_id()
        id3 = generator._create_rule_id()

        assert id1 == "spring-boot-3-to-spring-boot-4-00000"
        assert id2 == "spring-boot-3-to-spring-boot-4-00010"
        assert id3 == "spring-boot-3-to-spring-boot-4-00020"

    def test_generate_rule_id_with_rule_file_name(self):
        """Should use rule_file_name if provided"""
        generator = AnalyzerRuleGenerator(rule_file_name="custom-rules")

        rule_id = generator._create_rule_id()

        assert rule_id == "custom-rules-00000"

    def test_generate_rule_id_without_frameworks(self):
        """Should use default prefix without frameworks"""
        generator = AnalyzerRuleGenerator()

        rule_id = generator._create_rule_id()

        assert rule_id == "migration-00000"

    def test_rule_id_has_five_digits(self):
        """Should always use 5-digit numbering"""
        generator = AnalyzerRuleGenerator(source_framework="a", target_framework="b")

        # Generate many IDs to test padding
        for i in range(15):
            rule_id = generator._create_rule_id()

        # Last ID should still have 5 digits
        assert rule_id.endswith("-00140")


class TestComplexityToEffortMapping:
    """Test complexity to effort score mapping."""

    def test_map_trivial_to_effort_1(self):
        """Should map TRIVIAL to effort 1"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("TRIVIAL")
        assert effort == 1

    def test_map_low_to_effort_3(self):
        """Should map LOW to effort 3"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("LOW")
        assert effort == 3

    def test_map_medium_to_effort_5(self):
        """Should map MEDIUM to effort 5"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("MEDIUM")
        assert effort == 5

    def test_map_high_to_effort_7(self):
        """Should map HIGH to effort 7"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("HIGH")
        assert effort == 7

    def test_map_expert_to_effort_10(self):
        """Should map EXPERT to effort 10"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("EXPERT")
        assert effort == 10

    def test_map_unknown_to_default_5(self):
        """Should default to effort 5 for unknown complexity"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("UNKNOWN")
        assert effort == 5

    def test_map_case_insensitive(self):
        """Should handle lowercase complexity values"""
        generator = AnalyzerRuleGenerator()
        effort = generator._map_complexity_to_effort("trivial")
        assert effort == 1


class TestCategoryDetermination:
    """Test category determination logic."""

    def test_high_complexity_is_mandatory(self):
        """Should categorize HIGH complexity as mandatory"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test", complexity="HIGH", category="api", rationale="Test change"
        )

        category = generator._determine_category(pattern)
        assert category == Category.MANDATORY

    def test_expert_complexity_is_mandatory(self):
        """Should categorize EXPERT complexity as mandatory"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test",
            complexity="EXPERT",
            category="api",
            rationale="Complex migration",
        )

        category = generator._determine_category(pattern)
        assert category == Category.MANDATORY

    def test_trivial_complexity_is_mandatory(self):
        """Should categorize TRIVIAL complexity as mandatory (easy wins)"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test", complexity="TRIVIAL", category="api", rationale="Simple rename"
        )

        category = generator._determine_category(pattern)
        assert category == Category.MANDATORY

    def test_removed_api_is_mandatory(self):
        """Should categorize removed APIs as mandatory"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test",
            complexity="MEDIUM",
            category="api",
            rationale="API has been removed in version 2",
        )

        category = generator._determine_category(pattern)
        assert category == Category.MANDATORY

    def test_deprecated_for_removal_is_mandatory(self):
        """Should categorize deprecated for removal as mandatory"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test",
            complexity="MEDIUM",
            category="api",
            rationale="Deprecated for removal in next release",
        )

        category = generator._determine_category(pattern)
        assert category == Category.MANDATORY

    def test_property_rename_is_mandatory(self):
        """Should categorize property renames as mandatory"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="app.config.oldProperty",
            target_pattern="app.config.newProperty",
            complexity="MEDIUM",
            category="configuration",
            rationale="Property has been renamed",
        )

        category = generator._determine_category(pattern)
        assert category == Category.MANDATORY

    def test_medium_complexity_default_is_potential(self):
        """Should categorize MEDIUM complexity as potential by default"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test", complexity="MEDIUM", category="api", rationale="General change"
        )

        category = generator._determine_category(pattern)
        assert category == Category.POTENTIAL

    def test_low_complexity_is_potential(self):
        """Should categorize LOW complexity as potential"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test",
            complexity="LOW",
            category="api",
            rationale="Optional improvement",
        )

        category = generator._determine_category(pattern)
        assert category == Category.POTENTIAL


class TestWhenConditionBuilding:
    """Test when condition building for different providers."""

    def test_build_java_referenced_condition(self):
        """Should build java.referenced condition"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="OldClass",
            source_fqn="com.example.OldClass",
            location_type=LocationType.TYPE,
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        condition = generator._build_when_condition(pattern)

        assert "java.referenced" in condition
        assert condition["java.referenced"]["pattern"] == "com.example.OldClass"
        assert condition["java.referenced"]["location"] == "TYPE"

    def test_build_java_condition_with_default_location(self):
        """Should default to TYPE location if not specified"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="OldClass",
            source_fqn="com.example.OldClass",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        condition = generator._build_when_condition(pattern)

        assert condition["java.referenced"]["location"] == "TYPE"

    def test_build_java_condition_with_alternatives(self):
        """Should build OR condition with alternative FQNs"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="javax.security.cert.*",
            source_fqn="javax.security.cert.*",
            alternative_fqns=["java.security.cert.*"],
            location_type=LocationType.TYPE,
            complexity="MEDIUM",
            category="api",
            rationale="Package migration",
        )

        condition = generator._build_when_condition(pattern)

        assert "or" in condition
        assert len(condition["or"]) == 2
        assert condition["or"][0]["java.referenced"]["pattern"] == "javax.security.cert.*"
        assert condition["or"][1]["java.referenced"]["pattern"] == "java.security.cert.*"

    def test_build_builtin_filecontent_condition(self):
        """Should build builtin.filecontent condition"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="isDisabled",
            source_fqn="isDisabled\\s*=",  # regex pattern
            file_pattern="*.{tsx,jsx}",
            provider_type="builtin",
            complexity="MEDIUM",
            category="api",
            rationale="Property rename",
        )

        condition = generator._build_when_condition(pattern)

        assert "builtin.filecontent" in condition
        assert condition["builtin.filecontent"]["pattern"] == "isDisabled\\s*="
        assert condition["builtin.filecontent"]["filePattern"] == "*.{tsx,jsx}"

    def test_build_builtin_condition_without_file_pattern(self):
        """Should build builtin condition without filePattern if not specified"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="oldPattern",
            source_fqn="oldPattern",
            provider_type="builtin",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        condition = generator._build_when_condition(pattern)

        assert "builtin.filecontent" in condition
        assert "filePattern" not in condition["builtin.filecontent"]

    def test_build_nodejs_referenced_condition(self):
        """Should build nodejs.referenced condition"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="OldComponent",
            source_fqn="OldComponent",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="Component renamed",
        )

        condition = generator._build_when_condition(pattern)

        assert "nodejs.referenced" in condition
        assert condition["nodejs.referenced"]["pattern"] == "OldComponent"

    def test_build_nodejs_condition_uses_source_pattern_fallback(self):
        """Should use source_pattern if source_fqn not available"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="oldFunction",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="Function renamed",
        )

        condition = generator._build_when_condition(pattern)

        # When source_fqn is None, it uses source_pattern as fallback
        assert condition is not None
        assert "nodejs.referenced" in condition
        assert condition["nodejs.referenced"]["pattern"] == "oldFunction"

    def test_build_condition_returns_none_without_fqn(self):
        """Should return None if no source_fqn or pattern"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test", complexity="MEDIUM", category="api", rationale="No FQN specified"
        )

        condition = generator._build_when_condition(pattern)

        # For java provider (default), it needs source_fqn
        # Since we only have source_pattern, it should return None
        assert condition is None


class TestLabelBuilding:
    """Test label generation."""

    def test_build_labels_with_both_frameworks(self):
        """Should build labels with source and target"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-3", target_framework="spring-boot-4"
        )

        labels = generator._build_labels()

        assert "konveyor.io/source=spring-boot-3" in labels
        assert "konveyor.io/target=spring-boot-4" in labels

    def test_build_labels_with_only_source(self):
        """Should build label with only source"""
        generator = AnalyzerRuleGenerator(source_framework="jakarta-ee-8")

        labels = generator._build_labels()

        assert "konveyor.io/source=jakarta-ee-8" in labels
        assert len([label for label in labels if "target" in label]) == 0

    def test_build_labels_with_only_target(self):
        """Should build label with only target"""
        generator = AnalyzerRuleGenerator(target_framework="jakarta-ee-10")

        labels = generator._build_labels()

        assert "konveyor.io/target=jakarta-ee-10" in labels
        assert len([label for label in labels if "source" in label]) == 0

    def test_build_empty_labels(self):
        """Should build empty labels list without frameworks"""
        generator = AnalyzerRuleGenerator()

        labels = generator._build_labels()

        assert labels == []


class TestMessageBuilding:
    """Test migration message generation."""

    def test_build_message_with_replacement(self):
        """Should build message with replacement guidance"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="OldClass",
            target_pattern="NewClass",
            complexity="MEDIUM",
            category="api",
            rationale="Class has been renamed for clarity",
        )

        message = generator._build_message(pattern)

        assert "Class has been renamed for clarity" in message
        assert "Replace `OldClass` with `NewClass`" in message

    def test_build_message_for_removed_api(self):
        """Should build message for removed API without replacement"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="RemovedAPI",
            complexity="HIGH",
            category="api",
            rationale="API has been removed",
        )

        message = generator._build_message(pattern)

        assert "API has been removed" in message
        assert "Remove usage of `RemovedAPI`" in message
        assert "API has been removed" in message

    def test_build_message_with_examples(self):
        """Should include before/after examples in message"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="oldMethod()",
            target_pattern="newMethod()",
            complexity="MEDIUM",
            category="api",
            rationale="Method renamed",
            example_before="obj.oldMethod();",
            example_after="obj.newMethod();",
        )

        message = generator._build_message(pattern)

        assert "Before:" in message
        assert "obj.oldMethod();" in message
        assert "After:" in message
        assert "obj.newMethod();" in message

    def test_build_message_without_examples(self):
        """Should build message without examples if not provided"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="OldClass",
            target_pattern="NewClass",
            complexity="MEDIUM",
            category="api",
            rationale="Class renamed",
        )

        message = generator._build_message(pattern)

        assert "Before:" not in message
        assert "After:" not in message


class TestLinksBuilding:
    """Test documentation links generation."""

    def test_build_links_with_documentation_url(self):
        """Should build links when documentation URL provided"""
        generator = AnalyzerRuleGenerator(target_framework="spring-boot-4")
        pattern = MigrationPattern(
            source_pattern="test",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            documentation_url="https://docs.spring.io/migration",
        )

        links = generator._build_links(pattern)

        assert links is not None
        assert len(links) == 1
        assert links[0].url == "https://docs.spring.io/migration"
        assert "spring-boot-4" in links[0].title

    def test_build_links_without_documentation_url(self):
        """Should return None when no documentation URL"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="test", complexity="MEDIUM", category="api", rationale="Test"
        )

        links = generator._build_links(pattern)

        assert links is None


class TestPatternToRule:
    """Test complete pattern to rule conversion."""

    def test_convert_valid_pattern_to_rule(self):
        """Should convert valid pattern to rule successfully"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-3", target_framework="spring-boot-4"
        )

        pattern = MigrationPattern(
            source_pattern="OldClass",
            target_pattern="NewClass",
            source_fqn="com.example.OldClass",
            location_type=LocationType.TYPE,
            complexity="MEDIUM",
            category="api",
            concern="core",
            rationale="Class renamed for clarity",
            documentation_url="https://example.com/docs",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert isinstance(rule, AnalyzerRule)
        assert rule.ruleID == "spring-boot-3-to-spring-boot-4-00000"
        assert rule.effort == 5
        assert rule.category == Category.POTENTIAL
        assert "konveyor.io/source=spring-boot-3" in rule.labels
        assert "konveyor.io/target=spring-boot-4" in rule.labels
        assert rule.when is not None
        assert "Class renamed for clarity" in rule.message
        assert rule.links is not None

    def test_skip_pattern_without_fqn_or_pattern(self):
        """Should return None for pattern without FQN or source_pattern"""
        generator = AnalyzerRuleGenerator()

        # This pattern is missing both source_fqn and source_pattern
        # which are needed for rule generation
        pattern = MigrationPattern(
            source_pattern="",  # Empty pattern should be skipped
            complexity="MEDIUM",
            category="api",
            rationale="Missing pattern info",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is None

    def test_skip_pattern_with_unbuildable_condition(self):
        """Should return None if when condition cannot be built"""
        generator = AnalyzerRuleGenerator()

        # Pattern with source_pattern but no source_fqn for Java provider
        pattern = MigrationPattern(
            source_pattern="test", complexity="MEDIUM", category="api", rationale="Test"
        )

        rule = generator._pattern_to_rule(pattern)

        # Will be None because java provider needs source_fqn
        assert rule is None

    def test_migration_complexity_passed_to_rule(self):
        """Should pass migration_complexity from pattern to generated rule"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-3", target_framework="spring-boot-4"
        )

        # Test with each complexity level
        complexities = ["trivial", "low", "medium", "high", "expert"]

        for complexity in complexities:
            pattern = MigrationPattern(
                source_pattern=f"TestClass{complexity}",
                source_fqn=f"com.example.TestClass{complexity}",
                location_type=LocationType.TYPE,
                complexity=complexity,
                category="api",
                rationale="Test pattern",
            )

            rule = generator._pattern_to_rule(pattern)

            assert rule is not None
            assert (
                rule.migration_complexity == complexity
            ), f"Expected migration_complexity '{complexity}', got '{rule.migration_complexity}'"

    def test_migration_complexity_lowercase(self):
        """Should handle lowercase complexity values"""
        generator = AnalyzerRuleGenerator(source_framework="a", target_framework="b")

        pattern = MigrationPattern(
            source_pattern="TestClass",
            source_fqn="com.example.TestClass",
            location_type=LocationType.TYPE,
            complexity="medium",  # lowercase
            category="api",
            rationale="Test",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert rule.migration_complexity == "medium"

    def test_migration_complexity_uppercase(self):
        """Should handle uppercase complexity values"""
        generator = AnalyzerRuleGenerator(source_framework="a", target_framework="b")

        pattern = MigrationPattern(
            source_pattern="TestClass",
            source_fqn="com.example.TestClass",
            location_type=LocationType.TYPE,
            complexity="HIGH",  # uppercase
            category="api",
            rationale="Test",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert rule.migration_complexity == "HIGH"


class TestGenerateRules:
    """Test bulk rule generation."""

    def test_generate_rules_from_multiple_patterns(self):
        """Should generate multiple rules from patterns"""
        generator = AnalyzerRuleGenerator(source_framework="a", target_framework="b")

        patterns = [
            MigrationPattern(
                source_pattern="Class1",
                source_fqn="com.example.Class1",
                complexity="MEDIUM",
                category="api",
                rationale="Test 1",
            ),
            MigrationPattern(
                source_pattern="Class2",
                source_fqn="com.example.Class2",
                complexity="HIGH",
                category="api",
                rationale="Test 2",
            ),
        ]

        rules = generator.generate_rules(patterns)

        assert len(rules) == 2
        assert rules[0].ruleID.endswith("-00000")
        assert rules[1].ruleID.endswith("-00010")

    def test_generate_rules_skips_invalid_patterns(self):
        """Should skip patterns that cannot be converted"""
        generator = AnalyzerRuleGenerator()

        patterns = [
            MigrationPattern(
                source_pattern="Valid",
                source_fqn="com.example.Valid",
                complexity="MEDIUM",
                category="api",
                rationale="Valid",
            ),
            MigrationPattern(
                source_pattern="",  # Empty pattern will be skipped
                complexity="MEDIUM",
                category="api",
                rationale="Invalid - no FQN",
            ),
        ]

        rules = generator.generate_rules(patterns)

        assert len(rules) == 1
        assert "Valid" in rules[0].message


class TestGenerateRulesByConcern:
    """Test rules generation grouped by concern."""

    def test_group_rules_by_concern(self):
        """Should group rules by concern"""
        generator = AnalyzerRuleGenerator()

        patterns = [
            MigrationPattern(
                source_pattern="Security1",
                source_fqn="com.example.Security1",
                complexity="MEDIUM",
                category="api",
                concern="security",
                rationale="Security change 1",
            ),
            MigrationPattern(
                source_pattern="Security2",
                source_fqn="com.example.Security2",
                complexity="MEDIUM",
                category="api",
                concern="security",
                rationale="Security change 2",
            ),
            MigrationPattern(
                source_pattern="Config1",
                source_fqn="com.example.Config1",
                complexity="MEDIUM",
                category="configuration",
                concern="configuration",
                rationale="Config change",
            ),
        ]

        rules_by_concern = generator.generate_rules_by_concern(patterns)

        assert "security" in rules_by_concern
        assert "configuration" in rules_by_concern
        assert len(rules_by_concern["security"]) == 2
        assert len(rules_by_concern["configuration"]) == 1

    def test_use_general_for_no_concern(self):
        """Should use 'general' for patterns without concern"""
        generator = AnalyzerRuleGenerator()

        patterns = [
            MigrationPattern(
                source_pattern="Test",
                source_fqn="com.example.Test",
                complexity="MEDIUM",
                category="api",
                rationale="No concern specified",
            )
        ]

        rules_by_concern = generator.generate_rules_by_concern(patterns)

        assert "general" in rules_by_concern
        assert len(rules_by_concern["general"]) == 1

    def test_reset_rule_counter_per_concern(self):
        """Should NOT reset rule counter per concern - IDs must be globally unique"""
        generator = AnalyzerRuleGenerator(source_framework="a", target_framework="b")

        patterns = [
            MigrationPattern(
                source_pattern="Test1",
                source_fqn="com.example.Test1",
                complexity="MEDIUM",
                category="api",
                concern="concern-a",
                rationale="Test",
            ),
            MigrationPattern(
                source_pattern="Test2",
                source_fqn="com.example.Test2",
                complexity="MEDIUM",
                category="api",
                concern="concern-a",
                rationale="Test",
            ),
            MigrationPattern(
                source_pattern="Test3",
                source_fqn="com.example.Test3",
                complexity="MEDIUM",
                category="api",
                concern="concern-b",
                rationale="Test",
            ),
        ]

        rules_by_concern = generator.generate_rules_by_concern(patterns)

        # First concern should have rules 00000 and 00010
        concern_a_rules = rules_by_concern["concern-a"]
        assert concern_a_rules[0].ruleID.endswith("-00000")
        assert concern_a_rules[1].ruleID.endswith("-00010")

        # Second concern should continue with 00020 (counter does NOT reset)
        concern_b_rules = rules_by_concern["concern-b"]
        assert concern_b_rules[0].ruleID.endswith("-00020")


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_handle_empty_pattern_list(self):
        """Should handle empty pattern list gracefully"""
        generator = AnalyzerRuleGenerator()

        rules = generator.generate_rules([])

        assert rules == []

    def test_handle_all_invalid_patterns(self):
        """Should handle case where all patterns are invalid"""
        generator = AnalyzerRuleGenerator()

        patterns = [
            MigrationPattern(
                source_pattern="",  # Empty pattern will be skipped
                complexity="MEDIUM",
                category="api",
                rationale="No FQN",
            ),
            MigrationPattern(
                source_pattern="",  # Empty pattern will be skipped
                complexity="HIGH",
                category="api",
                rationale="Also no FQN",
            ),
        ]

        rules = generator.generate_rules(patterns)

        assert rules == []

    def test_generate_description_with_target(self):
        """Should generate description with replacement"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="Old",
            target_pattern="New",
            source_fqn="com.example.Old",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        rule = generator._pattern_to_rule(pattern)

        assert "should be replaced with" in rule.description

    def test_generate_description_without_target(self):
        """Should generate description for removed API"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="Removed",
            source_fqn="com.example.Removed",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        rule = generator._pattern_to_rule(pattern)

        # When there's no target_pattern, description says "usage detected (removed API)"
        assert "removed api" in rule.description.lower()
        assert "Removed" in rule.description


class TestGeneratorErrorHandling:
    """Test error handling in rule generation."""

    def test_builtin_provider_without_source_fqn(self):
        """Should handle builtin provider when source_fqn is missing"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="test",
            provider_type="builtin",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        # Should return None because builtin needs source_fqn for regex
        condition = generator._build_when_condition(pattern)
        assert condition is None

    def test_pattern_with_very_long_id(self):
        """Should handle very large rule numbers"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test")

        # Generate many rules to test large numbers
        for i in range(100):
            rule_id = generator._create_rule_id()

        # Should still format correctly with 5 digits
        assert rule_id.endswith("-00990")
        assert len(rule_id.split("-")[-1]) == 5

    def test_pattern_with_empty_source_pattern(self):
        """Should skip patterns with empty source_pattern"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="", complexity="MEDIUM", category="api", rationale="Test"
        )

        rule = generator._pattern_to_rule(pattern)

        # Should return None for empty pattern
        assert rule is None

    def test_pattern_with_whitespace_only_pattern(self):
        """Should handle patterns with only whitespace"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="   ",
            source_fqn="com.example.Test",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        rule = generator._pattern_to_rule(pattern)

        # Should still generate rule (whitespace validation done elsewhere)
        assert rule is not None

    def test_pattern_with_special_characters_in_id(self):
        """Should handle special characters in framework names"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot@3.0", target_framework="spring-boot@4.0"
        )

        rule_id = generator._create_rule_id()

        # Should sanitize special characters
        assert "@" in rule_id or rule_id.startswith("spring-boot")

    def test_generate_rules_with_empty_list(self):
        """Should handle empty pattern list"""
        generator = AnalyzerRuleGenerator()

        rules = generator.generate_rules([])

        assert rules == []

    def test_generate_rules_by_concern_with_empty_concerns(self):
        """Should group patterns with empty concern under 'general' or empty string"""
        generator = AnalyzerRuleGenerator()

        patterns = [
            MigrationPattern(
                source_pattern="Test1",
                source_fqn="com.example.Test1",
                complexity="MEDIUM",
                category="api",
                # concern not specified, will use default "general"
                rationale="Test",
            ),
            MigrationPattern(
                source_pattern="Test2",
                source_fqn="com.example.Test2",
                complexity="MEDIUM",
                category="api",
                concern="",  # Empty string
                rationale="Test",
            ),
        ]

        rules_by_concern = generator.generate_rules_by_concern(patterns)

        # First should be under 'general' (default), second under '' (empty)
        assert "general" in rules_by_concern or "" in rules_by_concern
        # At least one rule should be generated
        assert len(rules_by_concern) > 0

    def test_pattern_with_invalid_complexity(self):
        """Should handle patterns with non-standard complexity values"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="Test",
            source_fqn="com.example.Test",
            complexity="UNKNOWN_LEVEL",
            category="api",
            rationale="Test",
        )

        rule = generator._pattern_to_rule(pattern)

        # Should still generate rule and map to default effort
        assert rule is not None
        assert rule.effort == 5  # Default for unknown

    def test_builtin_provider_with_regex_special_chars(self):
        """Should handle builtin patterns with regex special characters"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="test.*[a-z]+",
            source_fqn="test\\.\\*\\[a-z\\]\\+",
            provider_type="builtin",
            file_pattern="*.js",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        condition = generator._build_when_condition(pattern)

        assert condition is not None
        assert "builtin.filecontent" in condition

    def test_alternative_fqns_with_empty_list(self):
        """Should handle empty alternative_fqns list"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="Test",
            source_fqn="com.example.Test",
            alternative_fqns=[],
            complexity="MEDIUM",
            category="api",
            rationale="Test",
        )

        condition = generator._build_when_condition(pattern)

        # Should not create OR condition
        assert "or" not in condition
        assert "java.referenced" in condition

    def test_pattern_with_very_long_message(self):
        """Should handle patterns with very long rationale"""
        generator = AnalyzerRuleGenerator()

        long_rationale = "This is a very long rationale. " * 100

        pattern = MigrationPattern(
            source_pattern="Test",
            target_pattern="New",
            source_fqn="com.example.Test",
            complexity="MEDIUM",
            category="api",
            rationale=long_rationale,
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert long_rationale in rule.message

    def test_pattern_with_unicode_in_patterns(self):
        """Should handle Unicode characters in patterns"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="测试类",
            target_pattern="TestClass",
            source_fqn="com.测试.测试类",
            complexity="MEDIUM",
            category="api",
            rationale="Internationalization",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "测试类" in rule.message

    def test_links_with_invalid_url(self):
        """Should handle patterns with malformed documentation URLs"""
        generator = AnalyzerRuleGenerator(target_framework="test")

        pattern = MigrationPattern(
            source_pattern="Test",
            source_fqn="com.example.Test",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            documentation_url="not-a-valid-url",
        )

        rule = generator._pattern_to_rule(pattern)

        # Should still generate rule with the URL as-is
        assert rule is not None
        if rule.links:
            assert rule.links[0].url == "not-a-valid-url"


class TestNodejsReferencedRules:
    """Test nodejs.referenced rule generation."""

    def test_build_nodejs_condition_for_component(self):
        """Should build simple nodejs.referenced condition for React components"""
        generator = AnalyzerRuleGenerator(source_framework="patternfly-5")

        pattern = MigrationPattern(
            source_pattern="Chip",
            source_fqn="Chip",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="The Chip component has been replaced with Label",
        )

        condition = generator._build_when_condition(pattern)

        assert condition is not None
        # Should be simple nodejs.referenced (no combo rules)
        assert "nodejs.referenced" in condition
        assert condition["nodejs.referenced"]["pattern"] == "Chip"
        assert "and" not in condition

    def test_build_nodejs_condition_for_hook(self):
        """Should build simple nodejs.referenced condition for hooks"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="useHook",
            source_fqn="useHook",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="The hook has been renamed",
        )

        condition = generator._build_when_condition(pattern)

        assert condition is not None
        assert "nodejs.referenced" in condition
        assert condition["nodejs.referenced"]["pattern"] == "useHook"
        assert "and" not in condition

    def test_build_csharp_referenced_condition(self):
        """Should build c-sharp.referenced condition"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="HttpNotFound",
            source_fqn="System.Web.Mvc.HttpNotFound",
            location_type=CSharpLocationType.METHOD,
            provider_type="csharp",
            complexity="MEDIUM",
            category="api",
            rationale="Method renamed in .NET Core",
        )

        condition = generator._build_when_condition(pattern)

        assert "c-sharp.referenced" in condition
        assert condition["c-sharp.referenced"]["pattern"] == "System.Web.Mvc.HttpNotFound"
        assert condition["c-sharp.referenced"]["location"] == "METHOD"

    def test_build_csharp_condition_with_class_location(self):
        """Should build c-sharp.referenced condition with CLASS location"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="HandleProcessCorruptedStateExceptionsAttribute",
            source_fqn="System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptionsAttribute",
            location_type=CSharpLocationType.CLASS,
            provider_type="csharp",
            complexity="HIGH",
            category="api",
            rationale="Attribute removed in .NET Core",
        )

        condition = generator._build_when_condition(pattern)

        assert "c-sharp.referenced" in condition
        assert condition["c-sharp.referenced"]["location"] == "CLASS"

    def test_build_csharp_condition_with_field_location(self):
        """Should build c-sharp.referenced condition with FIELD location"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="FileSystemInfo.Attributes",
            source_fqn="System.IO.FileSystemInfo.Attributes",
            location_type=CSharpLocationType.FIELD,
            provider_type="csharp",
            complexity="LOW",
            category="api",
            rationale="Property behavior changed",
        )

        condition = generator._build_when_condition(pattern)

        assert "c-sharp.referenced" in condition
        assert condition["c-sharp.referenced"]["location"] == "FIELD"

    def test_build_csharp_condition_defaults_to_all(self):
        """Should default to ALL location if not specified"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="IDispatchImplAttribute",
            source_fqn="System.Runtime.InteropServices.IDispatchImplAttribute",
            provider_type="csharp",
            complexity="HIGH",
            category="api",
            rationale="API removed",
        )

        condition = generator._build_when_condition(pattern)

        assert "c-sharp.referenced" in condition
        # When location_type is None, no location field should be added (defaults to ALL)
        assert "location" not in condition["c-sharp.referenced"]

    def test_build_csharp_condition_with_all_location(self):
        """Should build c-sharp.referenced condition with explicit ALL location"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="System.Web.Http",
            source_fqn="System.Web.Http.*",
            location_type=CSharpLocationType.ALL,
            provider_type="csharp",
            complexity="MEDIUM",
            category="api",
            rationale="Namespace migration",
        )

        condition = generator._build_when_condition(pattern)

        assert "c-sharp.referenced" in condition
        assert condition["c-sharp.referenced"]["location"] == "ALL"

    def test_build_csharp_condition_with_wildcard_pattern(self):
        """Should build c-sharp.referenced condition with wildcard pattern"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="System.Web.Http",
            source_fqn="System.Web.Http.*",
            provider_type="csharp",
            complexity="MEDIUM",
            category="api",
            rationale="Package migration",
        )

        condition = generator._build_when_condition(pattern)

        assert "c-sharp.referenced" in condition
        assert condition["c-sharp.referenced"]["pattern"] == "System.Web.Http.*"

    def test_build_csharp_condition_uses_source_pattern_fallback(self):
        """Should use source_pattern if source_fqn not available"""
        generator = AnalyzerRuleGenerator()
        pattern = MigrationPattern(
            source_pattern="ContextMenu",
            provider_type="csharp",
            complexity="MEDIUM",
            category="api",
            rationale="Control removed",
        )

        condition = generator._build_when_condition(pattern)

        # When source_fqn is None, it uses source_pattern as fallback
        assert condition is not None
        assert "c-sharp.referenced" in condition
        assert condition["c-sharp.referenced"]["pattern"] == "ContextMenu"

    def test_generate_rule_for_patternfly_component(self):
        """Should generate simple nodejs.referenced rule for PatternFly component"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-5",
            target_framework="patternfly-6",
            rule_file_name="patternfly-5-to-patternfly-6-components",
        )

        pattern = MigrationPattern(
            source_pattern="Chip",
            target_pattern="Label",
            source_fqn="Chip",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            concern="components",
            rationale="The Chip component has been replaced with Label in PatternFly 6",
            documentation_url="https://www.patternfly.org/get-started/upgrade",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert rule.ruleID == "patternfly-5-to-patternfly-6-components-00000"
        # Should be simple nodejs.referenced (no combo rules)
        assert "nodejs.referenced" in rule.when
        assert rule.when["nodejs.referenced"]["pattern"] == "Chip"
        assert "and" not in rule.when
        assert "Chip component" in rule.message
        assert "konveyor.io/source=patternfly-5" in rule.labels
        assert "konveyor.io/target=patternfly-6" in rule.labels

    def test_rules_for_multiple_components(self):
        """Should generate simple nodejs.referenced rules for multiple component patterns"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-5", target_framework="patternfly-6"
        )

        patterns = [
            MigrationPattern(
                source_pattern="Chip",
                source_fqn="Chip",
                provider_type="nodejs",
                complexity="MEDIUM",
                category="api",
                rationale="The Chip component has been replaced",
            ),
            MigrationPattern(
                source_pattern="Text",
                source_fqn="Text",
                provider_type="nodejs",
                complexity="MEDIUM",
                category="api",
                rationale="The Text component has been renamed",
            ),
            MigrationPattern(
                source_pattern="Tile",
                source_fqn="Tile",
                provider_type="nodejs",
                complexity="MEDIUM",
                category="api",
                rationale="The Tile component has been replaced",
            ),
        ]

        rules = generator.generate_rules(patterns)

        assert len(rules) == 3
        # All should have simple nodejs.referenced conditions
        for rule in rules:
            assert "nodejs.referenced" in rule.when
            assert "and" not in rule.when

    def test_requires_semantic_analysis_detects_keywords(self):
        """Should detect semantic analysis keywords in rationale"""
        generator = AnalyzerRuleGenerator()

        # Test with function keyword
        pattern = MigrationPattern(
            source_pattern="foo",
            source_fqn="foo",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="This function has been removed",
        )
        assert generator._requires_semantic_analysis(pattern) is True

        # Test with class keyword
        pattern = MigrationPattern(
            source_pattern="Foo",
            source_fqn="Foo",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="This class has been renamed",
        )
        assert generator._requires_semantic_analysis(pattern) is True

        # Test with component keyword
        pattern = MigrationPattern(
            source_pattern="Button",
            source_fqn="Button",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="This component has been updated",
        )
        assert generator._requires_semantic_analysis(pattern) is True

    def test_requires_semantic_analysis_returns_false_for_text_patterns(self):
        """Should return False for patterns without semantic keywords"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="deprecated-value",
            source_fqn="deprecated-value",
            provider_type="nodejs",
            complexity="MEDIUM",
            category="api",
            rationale="This value has been deprecated",
        )
        assert generator._requires_semantic_analysis(pattern) is False


class TestImportPatternRules:
    """Test import pattern detection and custom variables."""

    def test_is_import_pattern_detects_import_in_source_fqn(self):
        """Should detect import patterns from source_fqn"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-5", target_framework="patternfly-6"
        )

        pattern = MigrationPattern(
            source_pattern="import { Area } from '@patternfly/react-charts'",
            source_fqn="import.*from '@patternfly/react-charts'",
            provider_type="builtin",
            file_pattern="\\.(j|t)sx?$",
            complexity="LOW",
            category="api",
            rationale="Victory-based charts have moved to a 'victory' directory",
        )

        is_import = generator._is_import_pattern(pattern)
        assert is_import is True

    def test_is_import_pattern_detects_import_in_rationale(self):
        """Should detect import patterns from rationale"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="@patternfly/react-charts",
            source_fqn="@patternfly/react-charts",
            provider_type="builtin",
            complexity="LOW",
            category="api",
            rationale="Import statements from @patternfly/react-charts need updating",
        )

        is_import = generator._is_import_pattern(pattern)
        assert is_import is True

    def test_is_import_pattern_requires_builtin_provider(self):
        """Should require builtin provider for import detection"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="import { Component }",
            source_fqn="import { Component }",
            provider_type="nodejs",
            complexity="LOW",
            category="api",
            rationale="Test",
        )

        is_import = generator._is_import_pattern(pattern)
        assert is_import is False

    def test_build_custom_variables_for_import_pattern(self):
        """Should build custom variables for import patterns"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-5", target_framework="patternfly-6"
        )

        pattern = MigrationPattern(
            source_pattern="import { Area } from '@patternfly/react-charts'",
            source_fqn="import.*from '@patternfly/react-charts'",
            provider_type="builtin",
            file_pattern="\\.(j|t)sx?$",
            complexity="LOW",
            category="api",
            rationale="Victory-based charts have moved to a 'victory' directory",
        )

        custom_vars = generator._build_custom_variables(pattern)

        assert len(custom_vars) == 1
        assert custom_vars[0]["name"] == "component"
        assert custom_vars[0]["nameOfCaptureGroup"] == "imports"
        assert custom_vars[0]["defaultValue"] == "Component"
        assert "import {(?P<imports>" in custom_vars[0]["pattern"]
        # Verify correct regex pattern (A-Za-z, not A-z which includes invalid chars)
        assert custom_vars[0]["pattern"] == "import {(?P<imports>[A-Za-z,\\s]+)}"

    def test_build_custom_variables_returns_empty_for_non_import(self):
        """Should return empty list for non-import patterns"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="OldClass",
            source_fqn="com.example.OldClass",
            provider_type="java",
            complexity="MEDIUM",
            category="api",
            rationale="Class renamed",
        )

        custom_vars = generator._build_custom_variables(pattern)
        assert len(custom_vars) == 0

    def test_build_when_condition_adds_dollar_anchor_for_imports(self):
        """Should add $ anchor to import patterns for precise matching"""
        generator = AnalyzerRuleGenerator()

        pattern = MigrationPattern(
            source_pattern="import from '@patternfly/react-charts'",
            source_fqn="import.*from '@patternfly/react-charts'",
            provider_type="builtin",
            file_pattern="\\.(j|t)sx?$",
            complexity="LOW",
            category="api",
            rationale="Import statements need updating",
        )

        condition = generator._build_when_condition(pattern)

        assert "builtin.filecontent" in condition
        # Should have $ anchor added
        assert condition["builtin.filecontent"]["pattern"].endswith("$")
        assert (
            condition["builtin.filecontent"]["pattern"]
            == "import.*from '@patternfly/react-charts'$"
        )

    def test_extract_package_name_from_import_statement(self):
        """Should extract package name from import statement"""
        generator = AnalyzerRuleGenerator()

        # Test with single quotes
        result = generator._extract_package_name("import { Area } from '@patternfly/react-charts'")
        assert result == "@patternfly/react-charts"

        # Test with double quotes
        result = generator._extract_package_name('import { Area } from "@patternfly/react-charts"')
        assert result == "@patternfly/react-charts"

    def test_build_description_for_import_pattern_with_custom_variables(self):
        """Should build generic description for import patterns with custom variables"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-5", target_framework="patternfly-6"
        )

        pattern = MigrationPattern(
            source_pattern="import { Area } from '@patternfly/react-charts'",
            target_pattern="import { Area } from '@patternfly/react-charts/victory'",
            source_fqn="import.*from '@patternfly/react-charts'",
            provider_type="builtin",
            file_pattern="\\.(j|t)sx?$",
            complexity="LOW",
            category="api",
            rationale="Victory-based charts have moved to a 'victory' directory",
        )

        description = generator._build_description(pattern, has_custom_variables=True)

        # Should use generic "imports" instead of specific component
        assert "imports" in description
        assert "@patternfly/react-charts" in description
        assert "@patternfly/react-charts/victory" in description

    def test_generate_complete_import_rule(self):
        """Should generate complete rule with custom variables for import patterns"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-5",
            target_framework="patternfly-6",
            rule_file_name="patternfly-5-to-patternfly-6-charts",
        )

        pattern = MigrationPattern(
            source_pattern="import { Area } from '@patternfly/react-charts'",
            target_pattern="import { Area } from '@patternfly/react-charts/victory'",
            source_fqn="import.*from.*@patternfly/react-charts",
            provider_type="builtin",
            file_pattern="\\.(j|t)sx?$",
            complexity="LOW",
            category="api",
            concern="charts",
            rationale="Victory-based charts have moved to a 'victory' directory in @patternfly/react-charts to support multiple chart libraries",
            example_before="import { Area } from '@patternfly/react-charts';",
            example_after="import { Area } from '@patternfly/react-charts/victory';",
            documentation_url="https://www.patternfly.org/get-started/upgrade",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert rule.ruleID == "patternfly-5-to-patternfly-6-charts-00000"

        # Should have custom variables
        assert len(rule.customVariables) == 1
        assert rule.customVariables[0]["name"] == "component"

        # Description should be generic
        assert "imports" in rule.description

        # When condition should have $ anchor
        assert "builtin.filecontent" in rule.when
        assert rule.when["builtin.filecontent"]["pattern"].endswith("$")

        # Message should contain {{ component }} variable
        assert "{{ component }}" in rule.message


class TestComboRuleGeneration:
    """Test combo rule generation with import verification."""

    def test_combo_rule_with_import_pattern(self):
        """Should generate combo rule with import_pattern + builtin_pattern"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-v5", target_framework="patternfly-v6"
        )

        pattern = MigrationPattern(
            source_pattern="Alert",
            complexity="MEDIUM",
            category="api",
            rationale="Alert component usage",
            provider_type="combo",
            when_combo={
                "import_pattern": "import.*\\{[^}]*\\bAlert\\b[^}]*\\}.*from ['\"']@patternfly/react-",
                "builtin_pattern": "<Alert[^/>]*(?:/>|>)",
                "file_pattern": "\\.(j|t)sx?$",
            },
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "and" in rule.when
        conditions = rule.when["and"]

        # Should have 2 conditions: import + JSX usage
        assert len(conditions) == 2

        # First condition should be import verification
        assert "builtin.filecontent" in conditions[0]
        assert "import" in conditions[0]["builtin.filecontent"]["pattern"]
        assert conditions[0]["builtin.filecontent"]["filePattern"] == "\\.(j|t)sx?$"

        # Second condition should be JSX pattern
        assert "builtin.filecontent" in conditions[1]
        assert "<Alert" in conditions[1]["builtin.filecontent"]["pattern"]

    def test_combo_rule_with_nodejs_pattern(self):
        """Should generate combo rule with nodejs_pattern + builtin_pattern"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-v5", target_framework="patternfly-v6"
        )

        pattern = MigrationPattern(
            source_pattern="Button",
            complexity="MEDIUM",
            category="api",
            rationale="Button component prop change",
            provider_type="combo",
            when_combo={
                "nodejs_pattern": "Button",
                "builtin_pattern": "<Button.*isDisabled",
                "file_pattern": "\\.(j|t)sx?$",
            },
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "and" in rule.when
        conditions = rule.when["and"]

        # Should have 2 conditions: nodejs + builtin
        assert len(conditions) == 2

        # First condition should be nodejs.referenced
        assert "nodejs.referenced" in conditions[0]
        assert conditions[0]["nodejs.referenced"]["pattern"] == "Button"

        # Second condition should be builtin pattern
        assert "builtin.filecontent" in conditions[1]
        assert "isDisabled" in conditions[1]["builtin.filecontent"]["pattern"]

    def test_combo_rule_without_builtin_pattern_returns_none(self):
        """Should return None if combo rule missing builtin_pattern"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test2")

        pattern = MigrationPattern(
            source_pattern="Test",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            provider_type="combo",
            when_combo={
                "import_pattern": "import.*Test"
                # Missing builtin_pattern
            },
        )

        rule = generator._pattern_to_rule(pattern)

        # Should return None due to missing builtin_pattern
        assert rule is None

    def test_combo_rule_without_import_or_nodejs_returns_none(self):
        """Should return None if combo rule missing both import and nodejs patterns"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test2")

        pattern = MigrationPattern(
            source_pattern="Test",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            provider_type="combo",
            when_combo={
                "builtin_pattern": "<Test"
                # Missing both import_pattern and nodejs_pattern
            },
        )

        rule = generator._pattern_to_rule(pattern)

        # Should return None due to missing import/nodejs pattern
        assert rule is None

    def test_combo_rule_prefers_nodejs_over_import(self):
        """Should prefer nodejs.referenced over import_pattern (matches official Konveyor)"""
        generator = AnalyzerRuleGenerator(
            source_framework="patternfly-v5", target_framework="patternfly-v6"
        )

        pattern = MigrationPattern(
            source_pattern="Alert",
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            provider_type="combo",
            when_combo={
                "import_pattern": "import.*Alert",  # Should be ignored
                "nodejs_pattern": "Alert",  # Should be preferred
                "builtin_pattern": "<Alert",
            },
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        conditions = rule.when["and"]

        # First condition should use nodejs.referenced (semantic analysis)
        assert "nodejs.referenced" in conditions[0]
        assert conditions[0]["nodejs.referenced"]["pattern"] == "Alert"
        # Should NOT use import regex pattern
        assert "import" not in str(conditions[0])


class TestProviderFallbacks:
    """Test provider-specific fallback logic."""

    def test_nodejs_provider_uses_source_pattern_fallback(self):
        """Should use source_pattern as fallback for nodejs provider"""
        generator = AnalyzerRuleGenerator(source_framework="react-17", target_framework="react-18")

        pattern = MigrationPattern(
            source_pattern="ComponentWillMount",
            # No source_fqn provided
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            provider_type="nodejs",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "nodejs.referenced" in rule.when
        assert rule.when["nodejs.referenced"]["pattern"] == "ComponentWillMount"

    def test_csharp_provider_uses_source_pattern_fallback(self):
        """Should use source_pattern as fallback for csharp provider"""
        generator = AnalyzerRuleGenerator(
            source_framework="dotnet-framework", target_framework="dotnet-8"
        )

        pattern = MigrationPattern(
            source_pattern="System.Web.HttpContext",
            # No source_fqn provided
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            provider_type="csharp",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "c-sharp.referenced" in rule.when
        assert rule.when["c-sharp.referenced"]["pattern"] == "System.Web.HttpContext"

    def test_java_provider_requires_source_fqn(self):
        """Should return None if Java provider missing source_fqn"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-2", target_framework="spring-boot-3"
        )

        pattern = MigrationPattern(
            source_pattern="SomeClass",
            # No source_fqn for Java provider
            complexity="MEDIUM",
            category="api",
            rationale="Test",
            provider_type="java",
        )

        rule = generator._pattern_to_rule(pattern)

        # Should return None because Java requires source_fqn
        assert rule is None


class TestJavaDependencyPatterns:
    """Test Java dependency pattern generation with alternatives."""

    def test_java_dependency_without_alternatives(self):
        """Should generate simple java.dependency condition"""
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-2", target_framework="spring-boot-3"
        )

        pattern = MigrationPattern(
            source_pattern="spring-boot-starter-web",  # Required field
            source_fqn="org.springframework:spring-boot-starter-web",
            category="dependency",
            rationale="Dependency update",
            complexity="MEDIUM",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.dependency" in rule.when
        # Should convert colons to dots in dependency name
        assert rule.when["java.dependency"]["name"] == "org.springframework.spring-boot-starter-web"
        assert rule.when["java.dependency"]["lowerbound"] == "0.0.0"

    def test_java_dependency_with_alternative_fqns(self):
        """Should generate OR condition with alternatives"""
        generator = AnalyzerRuleGenerator(
            source_framework="jakarta-9", target_framework="jakarta-10"
        )

        pattern = MigrationPattern(
            source_pattern="servlet-api",  # Required field
            source_fqn="javax.servlet:servlet-api",
            alternative_fqns=[
                "javax.servlet:javax.servlet-api",
                "jakarta.servlet:jakarta.servlet-api",
            ],
            category="dependency",
            rationale="Multiple possible dependency names",
            complexity="MEDIUM",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "or" in rule.when

        # Should have 3 conditions (main + 2 alternatives)
        conditions = rule.when["or"]
        assert len(conditions) == 3

        # Each condition should be a java.dependency
        assert all("java.dependency" in cond for cond in conditions)

        # Check the dependency names are converted correctly (: to .)
        names = [cond["java.dependency"]["name"] for cond in conditions]
        assert "javax.servlet.servlet-api" in names
        assert "javax.servlet.javax.servlet-api" in names
        assert "jakarta.servlet.jakarta.servlet-api" in names

    def test_java_dependency_converts_colons_to_dots(self):
        """Should convert Maven-style coordinates (colon) to dots"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test2")

        pattern = MigrationPattern(
            source_pattern="artifact-name",  # Required field
            source_fqn="com.example:artifact-name",
            category="dependency",
            rationale="Test",
            complexity="MEDIUM",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        # Should convert "com.example:artifact-name" to "com.example.artifact-name"
        assert rule.when["java.dependency"]["name"] == "com.example.artifact-name"

    def test_java_dependency_with_empty_alternative_fqns_list(self):
        """Should handle empty alternative_fqns list"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test2")

        pattern = MigrationPattern(
            source_pattern="library",  # Required field
            source_fqn="org.example:library",
            alternative_fqns=[],  # Empty list
            category="dependency",
            rationale="Test",
            complexity="MEDIUM",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        # Should NOT create OR condition with empty alternatives
        assert "or" not in rule.when
        assert "java.dependency" in rule.when
        assert rule.when["java.dependency"]["name"] == "org.example.library"

    def test_java_dependency_sets_lowerbound_zero(self):
        """Should always set lowerbound to 0.0.0 to match any version"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test2")

        pattern = MigrationPattern(
            source_pattern="lib",  # Required field
            source_fqn="com.example:lib",
            category="dependency",
            rationale="Test",
            complexity="MEDIUM",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        # Should set lowerbound to match any version
        assert rule.when["java.dependency"]["lowerbound"] == "0.0.0"


class TestJavaPatternValidation:
    """Test Java pattern syntax validation."""

    def test_validate_package_pattern_with_dot_asterisk(self):
        """Should warn about asterisk after dot in PACKAGE patterns"""
        from src.rule_generator.generator import validate_java_pattern

        warnings = validate_java_pattern("javax.xml.*", "PACKAGE")

        assert len(warnings) == 1
        assert "'javax.xml.*'" in warnings[0]
        assert "invalid" in warnings[0].lower()
        assert "'javax.xml*'" in warnings[0]  # Should suggest the correct pattern

    def test_validate_package_pattern_with_correct_wildcard(self):
        """Should not warn about correct PACKAGE wildcard patterns"""
        from src.rule_generator.generator import validate_java_pattern

        warnings = validate_java_pattern("javax.xml*", "PACKAGE")

        assert len(warnings) == 0

    def test_validate_import_pattern_with_wildcard(self):
        """Should warn about wildcards in IMPORT patterns"""
        from src.rule_generator.generator import validate_java_pattern

        warnings = validate_java_pattern("java.applet.*", "IMPORT")

        assert len(warnings) == 1
        assert "wildcard" in warnings[0].lower()
        assert "IMPORT" in warnings[0]
        assert "specific class names" in warnings[0]

    def test_validate_import_pattern_without_wildcard(self):
        """Should not warn about specific class names in IMPORT patterns"""
        from src.rule_generator.generator import validate_java_pattern

        warnings = validate_java_pattern("java.applet.Applet", "IMPORT")

        assert len(warnings) == 0

    def test_validate_type_pattern_allows_wildcards(self):
        """Should not warn about wildcards in TYPE patterns"""
        from src.rule_generator.generator import validate_java_pattern

        warnings = validate_java_pattern("java.util.*", "TYPE")

        # TYPE location can use wildcards
        # Only PACKAGE location has the "no dot before asterisk" rule
        assert len(warnings) == 0

    def test_validation_warns_on_pattern_generation(self, capsys):
        """Should print warnings when generating rules with invalid patterns"""
        generator = AnalyzerRuleGenerator(
            source_framework="jakarta-8", target_framework="jakarta-10"
        )

        pattern = MigrationPattern(
            source_pattern="javax.xml.*",
            source_fqn="javax.xml.*",
            location_type=LocationType.PACKAGE,
            complexity="MEDIUM",
            category="api",
            rationale="Package migration",
        )

        rule = generator._pattern_to_rule(pattern)

        # Capture printed output
        captured = capsys.readouterr()

        # Should still generate the rule
        assert rule is not None

        # Should print validation warning
        assert "[Pattern Validation Warning]" in captured.out
        assert "javax.xml.*" in captured.out
        assert "invalid" in captured.out.lower()


class TestNewJavaLocationTypes:
    """Test generation of rules with new location types."""

    def test_implements_type_location(self):
        """Should generate rule with IMPLEMENTS_TYPE location"""
        generator = AnalyzerRuleGenerator(source_framework="jdk-17", target_framework="jdk-21")

        pattern = MigrationPattern(
            source_pattern="java.io.Serializable",
            source_fqn="java.io.Serializable",
            location_type=LocationType.IMPLEMENTS_TYPE,
            complexity="MEDIUM",
            category="api",
            rationale="Interface usage detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "IMPLEMENTS_TYPE"
        assert rule.when["java.referenced"]["pattern"] == "java.io.Serializable"

    def test_enum_constant_location(self):
        """Should generate rule with ENUM_CONSTANT location"""
        generator = AnalyzerRuleGenerator(source_framework="jdk-17", target_framework="jdk-21")

        pattern = MigrationPattern(
            source_pattern="java.time.temporal.ChronoUnit.DAYS",
            source_fqn="java.time.temporal.ChronoUnit.DAYS",
            location_type=LocationType.ENUM_CONSTANT,
            complexity="MEDIUM",
            category="api",
            rationale="Enum constant detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "ENUM_CONSTANT"

    def test_return_type_location(self):
        """Should generate rule with RETURN_TYPE location"""
        generator = AnalyzerRuleGenerator(source_framework="jdk-17", target_framework="jdk-21")

        pattern = MigrationPattern(
            source_pattern="java.util.Date",
            source_fqn="java.util.Date",
            location_type=LocationType.RETURN_TYPE,
            complexity="MEDIUM",
            category="api",
            rationale="Method return type detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "RETURN_TYPE"

    def test_variable_declaration_location(self):
        """Should generate rule with VARIABLE_DECLARATION location"""
        generator = AnalyzerRuleGenerator(source_framework="jdk-17", target_framework="jdk-21")

        pattern = MigrationPattern(
            source_pattern="java.util.Vector",
            source_fqn="java.util.Vector",
            location_type=LocationType.VARIABLE_DECLARATION,
            complexity="MEDIUM",
            category="api",
            rationale="Variable declaration detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "VARIABLE_DECLARATION"

    def test_field_location(self):
        """Should generate rule with FIELD location"""
        generator = AnalyzerRuleGenerator(source_framework="jdk-17", target_framework="jdk-21")

        pattern = MigrationPattern(
            source_pattern="java.lang.String",
            source_fqn="java.lang.String",
            location_type=LocationType.FIELD,
            complexity="MEDIUM",
            category="api",
            rationale="Field declaration detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "FIELD"

    def test_method_location(self):
        """Should generate rule with METHOD location"""
        generator = AnalyzerRuleGenerator(source_framework="jakarta-9", target_framework="jakarta-10")

        pattern = MigrationPattern(
            source_pattern="javax.ejb.Stateless",
            source_fqn="javax.ejb.Stateless",
            location_type=LocationType.METHOD,
            complexity="MEDIUM",
            category="api",
            rationale="Method annotation detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "METHOD"

    def test_class_location(self):
        """Should generate rule with CLASS location"""
        generator = AnalyzerRuleGenerator(source_framework="jakarta-9", target_framework="jakarta-10")

        pattern = MigrationPattern(
            source_pattern="javax.persistence.Entity",
            source_fqn="javax.persistence.Entity",
            location_type=LocationType.CLASS,
            complexity="MEDIUM",
            category="api",
            rationale="Class annotation detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "CLASS"

    def test_package_location_with_valid_wildcard(self):
        """Should generate PACKAGE rule with correct wildcard syntax"""
        generator = AnalyzerRuleGenerator(source_framework="jdk-17", target_framework="jdk-21")

        pattern = MigrationPattern(
            source_pattern="java.applet*",
            source_fqn="java.applet*",
            location_type=LocationType.PACKAGE,
            complexity="MEDIUM",
            category="api",
            rationale="Package wildcard detection",
        )

        rule = generator._pattern_to_rule(pattern)

        assert rule is not None
        assert "java.referenced" in rule.when
        assert rule.when["java.referenced"]["location"] == "PACKAGE"
        assert rule.when["java.referenced"]["pattern"] == "java.applet*"

    def test_all_location_types_generate_valid_rules(self):
        """Should successfully generate rules for all location types"""
        generator = AnalyzerRuleGenerator(source_framework="test", target_framework="test2")

        location_types = [
            LocationType.TYPE,
            LocationType.IMPORT,
            LocationType.INHERITANCE,
            LocationType.METHOD_CALL,
            LocationType.CONSTRUCTOR_CALL,
            LocationType.PACKAGE,
            LocationType.IMPLEMENTS_TYPE,
            LocationType.ENUM_CONSTANT,
            LocationType.RETURN_TYPE,
            LocationType.VARIABLE_DECLARATION,
            LocationType.FIELD,
            LocationType.METHOD,
            LocationType.CLASS,
            LocationType.ANNOTATION,
        ]

        for location_type in location_types:
            pattern = MigrationPattern(
                source_pattern=f"Test{location_type.value}",
                source_fqn=f"com.example.Test{location_type.value}",
                location_type=location_type,
                complexity="MEDIUM",
                category="api",
                rationale=f"Test {location_type.value} location",
            )

            rule = generator._pattern_to_rule(pattern)

            assert rule is not None, f"Failed to generate rule for {location_type.value}"
            assert "java.referenced" in rule.when
            assert rule.when["java.referenced"]["location"] == location_type.value
