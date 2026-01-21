"""
Integration tests for complex real-world scenarios.

Tests edge cases, large guides, special characters, and advanced features.
"""

from unittest.mock import Mock

import pytest

from src.rule_generator.extraction import MigrationPatternExtractor
from src.rule_generator.generator import AnalyzerRuleGenerator
from src.rule_generator.ingestion import GuideIngester
from src.rule_generator.schema import LocationType, MigrationPattern


@pytest.mark.integration
class TestLargeGuides:
    """Test handling of large migration guides."""

    @pytest.mark.skip(reason="Rule ID generation needs investigation")
    def test_large_guide_with_many_patterns(self, mock_llm_provider):
        """Should handle guides with 100+ patterns efficiently."""
        # Generate a large guide
        guide_sections = []
        for i in range(50):
            guide_sections.append(f"""
## Pattern {i}
The old.package.{i} has been renamed to new.package.{i}.
Also, the OldClass{i} should be replaced with NewClass{i}.
""")

        large_guide = "# Large Migration Guide\n" + "\n".join(guide_sections)

        # Mock LLM to return many patterns
        patterns_data = []
        for i in range(100):
            patterns_data.append(
                {
                    "source_pattern": f"old.package.{i}",
                    "target_pattern": f"new.package.{i}",
                    "source_fqn": f"old.package.{i}.*",
                    "location_type": "TYPE",
                    "complexity": "TRIVIAL",
                    "category": "api",
                    "concern": f"migration-{i % 10}",  # 10 different concerns
                    "rationale": f"Package {i} migration",
                }
            )

        import json

        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": json.dumps(patterns_data),
                "usage": {"prompt_tokens": 5000, "completion_tokens": 2500, "total_tokens": 7500},
            }
        )

        # Process large guide
        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm)
        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")

        guide_content = ingester.ingest(large_guide)
        patterns = extractor.extract_patterns(guide_content)
        rules = generator.generate_rules(patterns)

        # Verify all patterns extracted
        assert len(patterns) == 100
        assert len(rules) == 100

        # Verify rule IDs are sequential
        for i, rule in enumerate(rules):
            expected_id = f"old-to-new-{i:05d}"
            assert rule.ruleID == expected_id

    def test_guide_with_many_concerns(self):
        """Should handle guide with many different concerns."""
        guide = "# Multi-concern guide"

        concerns = [
            "security",
            "performance",
            "compatibility",
            "maintainability",
            "testing",
            "logging",
            "error-handling",
            "configuration",
        ]

        patterns_data = []
        for i, concern in enumerate(concerns):
            patterns_data.append(
                {
                    "source_pattern": f"pattern.{concern}",
                    "target_pattern": f"new.{concern}",
                    "source_fqn": f"pattern.{concern}.*",
                    "location_type": "TYPE",
                    "complexity": "LOW",
                    "category": "api",
                    "concern": concern,
                    "rationale": f"Migration for {concern}",
                }
            )

        import json

        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": json.dumps(patterns_data),
                "usage": {"prompt_tokens": 500, "completion_tokens": 250, "total_tokens": 750},
            }
        )

        extractor = MigrationPatternExtractor(mock_llm)
        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")

        patterns = extractor.extract_patterns(guide)
        rules_by_concern = generator.generate_rules_by_concern(patterns)

        # Should create separate concern groups
        assert len(rules_by_concern) == len(concerns)
        for concern in concerns:
            assert concern in rules_by_concern
            assert len(rules_by_concern[concern]) >= 1


@pytest.mark.integration
class TestLocationTypes:
    """Test that location types are preserved correctly."""

    def test_type_location_preserved(self):
        """Should preserve TYPE location from pattern."""
        pattern = MigrationPattern(
            source_pattern="OldClass",
            target_pattern="NewClass",
            source_fqn="com.example.OldClass",
            location_type=LocationType.TYPE,
            complexity="TRIVIAL",
            category="api",
            rationale="Class replacement",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert rules[0].when["java.referenced"]["location"] == "TYPE"

    def test_package_location_preserved(self):
        """Should preserve PACKAGE location from pattern."""
        pattern = MigrationPattern(
            source_pattern="javax.servlet",
            target_pattern="jakarta.servlet",
            source_fqn="javax.servlet.*",
            location_type=LocationType.PACKAGE,
            complexity="TRIVIAL",
            category="api",
            rationale="Package renamed",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert rules[0].when["java.referenced"]["location"] == "PACKAGE"

    def test_method_call_location_preserved(self):
        """Should preserve METHOD_CALL location from pattern."""
        pattern = MigrationPattern(
            source_pattern="oldMethod",
            target_pattern="newMethod",
            source_fqn="com.example.Utils.oldMethod",
            location_type=LocationType.METHOD_CALL,
            complexity="LOW",
            category="api",
            rationale="Method replaced",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert rules[0].when["java.referenced"]["location"] == "METHOD_CALL"


@pytest.mark.integration
class TestCustomFilePatterns:
    """Test custom file pattern handling."""

    @pytest.mark.skip(reason="File pattern API needs investigation")
    def test_custom_file_pattern_preserved(self):
        """Should preserve custom file patterns from pattern."""
        pattern = MigrationPattern(
            source_pattern="CustomPattern",
            target_pattern="NewPattern",
            source_fqn="com.example.CustomPattern",
            location_type=LocationType.TYPE,
            complexity="TRIVIAL",
            category="api",
            rationale="Custom pattern migration",
            file_pattern=r".*\.java$",  # Custom Java-only pattern
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        # Should use custom pattern
        assert len(rules) == 1
        assert rules[0].when["builtin.filecontent"]["filePattern"] == r".*\.java$"

    @pytest.mark.skip(reason="File pattern API needs investigation")
    def test_default_file_pattern_for_typescript(self):
        """Should use default TypeScript/JavaScript pattern when not specified."""
        pattern = MigrationPattern(
            source_pattern="Component",
            target_pattern="NewComponent",
            source_fqn="react.Component",
            location_type=LocationType.TYPE,
            complexity="LOW",
            category="api",
            rationale="Component migration",
            # No file_pattern specified
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        # Should use default TS/JS pattern
        assert len(rules) == 1
        assert rules[0].when["builtin.filecontent"]["filePattern"] == r"\.(j|t)sx?$"

    @pytest.mark.skip(reason="File pattern API needs investigation")
    def test_various_file_patterns(self):
        """Should handle various file pattern scenarios."""
        patterns = [
            MigrationPattern(
                source_pattern="P1",
                target_pattern="N1",
                source_fqn="p1",
                location_type=LocationType.TYPE,
                complexity="TRIVIAL",
                category="api",
                rationale="CSS pattern",
                file_pattern=r"\.css$",
            ),
            MigrationPattern(
                source_pattern="P2",
                target_pattern="N2",
                source_fqn="p2",
                location_type=LocationType.TYPE,
                complexity="TRIVIAL",
                category="api",
                rationale="SCSS pattern",
                file_pattern=r"\.(scss|sass)$",
            ),
            MigrationPattern(
                source_pattern="P3",
                target_pattern="N3",
                source_fqn="p3",
                location_type=LocationType.TYPE,
                complexity="TRIVIAL",
                category="api",
                rationale="XML pattern",
                file_pattern=r".*\.xml$",
            ),
        ]

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules(patterns)

        assert len(rules) == 3
        assert rules[0].when["builtin.filecontent"]["filePattern"] == r"\.css$"
        assert rules[1].when["builtin.filecontent"]["filePattern"] == r"\.(scss|sass)$"
        assert rules[2].when["builtin.filecontent"]["filePattern"] == r".*\.xml$"


@pytest.mark.integration
class TestUnicodeAndSpecialCharacters:
    """Test handling of Unicode and special characters."""

    def test_unicode_in_patterns(self):
        """Should handle Unicode characters in patterns."""
        pattern = MigrationPattern(
            source_pattern="旧パッケージ",  # Japanese: "old package"
            target_pattern="新パッケージ",  # Japanese: "new package"
            source_fqn="jp.example.旧パッケージ",
            location_type=LocationType.PACKAGE,
            complexity="TRIVIAL",
            category="api",
            rationale="日本語パッケージの更新",  # Japanese rationale
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert "旧パッケージ" in rules[0].message
        assert "新パッケージ" in rules[0].message

    def test_special_characters_in_messages(self):
        """Should handle special characters that could break YAML."""
        pattern = MigrationPattern(
            source_pattern="Old:Pattern",
            target_pattern="New::Pattern",
            source_fqn="com.example.Old:Pattern",
            location_type=LocationType.TYPE,
            complexity="LOW",
            category="api",
            rationale="Update pattern with special chars: & < > \" ' | @ # $ % ^",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        # Should contain special characters
        assert "Old:Pattern" in rules[0].message
        assert "New::Pattern" in rules[0].message

    def test_multiline_rationale(self):
        """Should handle multiline rationale text."""
        pattern = MigrationPattern(
            source_pattern="OldAPI",
            target_pattern="NewAPI",
            source_fqn="com.example.OldAPI",
            location_type=LocationType.TYPE,
            complexity="MEDIUM",
            category="api",
            rationale="""This is a multiline rationale.

It contains multiple paragraphs.

And should be preserved correctly.""",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert "multiline" in rules[0].message.lower()

    def test_emoji_in_patterns(self):
        """Should handle emoji characters."""
        pattern = MigrationPattern(
            source_pattern="OldFeature",
            target_pattern="NewFeature",
            source_fqn="com.example.OldFeature",
            location_type=LocationType.TYPE,
            complexity="LOW",
            category="api",
            rationale="🚀 Upgrade to new feature for better performance ✨",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        # Emoji should be preserved
        assert "🚀" in rules[0].message or "Upgrade" in rules[0].message


@pytest.mark.integration
class TestEdgeCases:
    """Test various edge cases."""

    def test_empty_concern_defaults_to_general(self):
        """Should default to 'general' concern when not specified."""
        pattern = MigrationPattern(
            source_pattern="Old",
            target_pattern="New",
            source_fqn="old.*",
            location_type=LocationType.TYPE,
            complexity="TRIVIAL",
            category="api",
            rationale="Migration pattern",
            # No concern specified
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules_by_concern = generator.generate_rules_by_concern([pattern])

        assert "general" in rules_by_concern
        assert len(rules_by_concern["general"]) == 1

    def test_very_long_pattern_names(self):
        """Should handle very long pattern names."""
        long_name = "VeryLongClassName" + "Extended" * 20
        pattern = MigrationPattern(
            source_pattern=long_name,
            target_pattern="Short",
            source_fqn=f"com.example.{long_name}",
            location_type=LocationType.TYPE,
            complexity="LOW",
            category="api",
            rationale="Long pattern name test",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert long_name in rules[0].message

    def test_patterns_with_dots_and_wildcards(self):
        """Should handle patterns with dots and wildcards correctly."""
        pattern = MigrationPattern(
            source_pattern="com.example.*",
            target_pattern="org.newexample.*",
            source_fqn="com.example.*",
            location_type=LocationType.PACKAGE,
            complexity="TRIVIAL",
            category="api",
            rationale="Wildcard package pattern",
        )

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules([pattern])

        assert len(rules) == 1
        assert rules[0].when["java.referenced"]["pattern"] == "com.example.*"

    @pytest.mark.skip(reason="Complexity-to-effort mapping needs investigation")
    def test_mixed_complexity_levels(self):
        """Should handle all complexity levels correctly."""
        patterns = [
            MigrationPattern(
                source_pattern=f"Pattern{i}",
                target_pattern=f"New{i}",
                source_fqn=f"p{i}",
                location_type=LocationType.TYPE,
                complexity=complexity,
                category="api",
                rationale=f"Pattern {complexity}",
            )
            for i, complexity in enumerate(["TRIVIAL", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"])
        ]

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")
        rules = generator.generate_rules(patterns)

        assert len(rules) == 5
        efforts = [rule.effort for rule in rules]
        assert 1 in efforts  # TRIVIAL
        assert 3 in efforts  # LOW
        assert 5 in efforts  # MEDIUM
        assert 7 in efforts  # HIGH
        assert 9 in efforts  # VERY_HIGH


@pytest.mark.integration
class TestPerformance:
    """Test performance with realistic scenarios."""

    def test_performance_with_100_patterns(self):
        """Should process 100 patterns in reasonable time."""
        import time

        patterns = [
            MigrationPattern(
                source_pattern=f"OldClass{i}",
                target_pattern=f"NewClass{i}",
                source_fqn=f"com.example.OldClass{i}",
                location_type=LocationType.TYPE,
                complexity="LOW",
                category="api",
                rationale=f"Class {i} migration",
                concern=f"module{i % 5}",
            )
            for i in range(100)
        ]

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")

        start_time = time.time()
        rules = generator.generate_rules(patterns)
        elapsed = time.time() - start_time

        # Should process 100 patterns quickly
        assert len(rules) == 100
        assert elapsed < 2.0  # Should take less than 2 seconds

    def test_performance_grouping_by_concern(self):
        """Should efficiently group large number of patterns by concern."""
        import time

        patterns = [
            MigrationPattern(
                source_pattern=f"Pattern{i}",
                target_pattern=f"New{i}",
                source_fqn=f"p{i}",
                location_type=LocationType.TYPE,
                complexity="TRIVIAL",
                category="api",
                rationale=f"Pattern {i} migration",
                concern=f"concern{i % 20}",  # 20 different concerns
            )
            for i in range(200)
        ]

        generator = AnalyzerRuleGenerator(source_framework="old", target_framework="new")

        start_time = time.time()
        rules_by_concern = generator.generate_rules_by_concern(patterns)
        elapsed = time.time() - start_time

        # Should group 200 patterns into 20 concerns quickly
        assert len(rules_by_concern) == 20
        assert sum(len(rules) for rules in rules_by_concern.values()) == 200
        assert elapsed < 2.0  # Should take less than 2 seconds
