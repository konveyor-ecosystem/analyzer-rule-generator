"""
Integration tests for OpenRewrite recipe conversion.

Tests converting OpenRewrite recipes to Konveyor analyzer rules.
"""

from unittest.mock import Mock

import pytest
import yaml

from src.rule_generator.extraction import MigrationPatternExtractor
from src.rule_generator.generator import AnalyzerRuleGenerator
from src.rule_generator.ingestion import GuideIngester


@pytest.mark.integration
class TestOpenRewriteChangePackage:
    """Test ChangePackage recipe conversion."""

    def test_change_package_to_rules(self, tmp_path):
        """Should convert ChangePackage recipe to analyzer rules."""
        # OpenRewrite recipe
        recipe = """---
type: specs.openrewrite.org/v1beta/recipe
name: com.example.PackageMigration
displayName: Package Migration
recipeList:
  - org.openrewrite.java.ChangePackage:
      oldPackageName: javax.servlet
      newPackageName: jakarta.servlet
"""

        # Mock LLM response
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[{
                "source_pattern": "javax.servlet",
                "target_pattern": "jakarta.servlet",
                "source_fqn": "javax.servlet.*",
                "location_type": "TYPE",
                "complexity": "TRIVIAL",
                "category": "api",
                "concern": "jakarta-migration",
                "rationale": "Package renamed from javax.servlet to jakarta.servlet in Jakarta EE 9+",
                "example_before": "import javax.servlet.HttpServlet;",
                "example_after": "import jakarta.servlet.HttpServlet;"
            }]""",
                "usage": {"prompt_tokens": 150, "completion_tokens": 75, "total_tokens": 225},
            }
        )

        # Setup components
        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator(source_framework="javax", target_framework="jakarta")

        # Convert recipe
        recipe_content = ingester.ingest(recipe)
        patterns = extractor.extract_patterns(
            recipe_content, source_framework="javax", target_framework="jakarta"
        )
        rules = generator.generate_rules(patterns)

        # Verify
        assert len(patterns) == 1
        assert patterns[0].source_pattern == "javax.servlet"
        assert patterns[0].target_pattern == "jakarta.servlet"
        assert patterns[0].source_fqn == "javax.servlet.*"
        assert patterns[0].location_type.value == "TYPE"

        assert len(rules) == 1
        assert "java.referenced" in rules[0].when
        assert rules[0].when["java.referenced"]["pattern"] == "javax.servlet.*"
        assert rules[0].when["java.referenced"]["location"] == "TYPE"
        assert "javax.servlet" in rules[0].message
        assert "jakarta.servlet" in rules[0].message

    def test_change_package_from_file(self, tmp_path):
        """Should load and convert ChangePackage recipe from YAML file."""
        # Write recipe to file
        recipe_file = tmp_path / "recipe.yml"
        recipe_file.write_text("""---
recipeList:
  - org.openrewrite.java.ChangePackage:
      oldPackageName: com.sun.net.ssl
      newPackageName: javax.net.ssl
""")

        # Mock LLM
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[{
                "source_pattern": "com.sun.net.ssl",
                "target_pattern": "javax.net.ssl",
                "source_fqn": "com.sun.net.ssl.*",
                "location_type": "TYPE",
                "complexity": "TRIVIAL",
                "category": "api",
                "rationale": "Package migrated to javax.net.ssl"
            }]""",
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
        )

        # Process
        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator()

        recipe_content = ingester.ingest(str(recipe_file))
        patterns = extractor.extract_patterns(recipe_content)
        rules = generator.generate_rules(patterns)

        # Verify
        assert len(patterns) == 1
        assert patterns[0].source_fqn == "com.sun.net.ssl.*"
        assert len(rules) == 1


@pytest.mark.integration
class TestOpenRewriteChangeType:
    """Test ChangeType recipe conversion."""

    def test_change_type_to_rules(self):
        """Should convert ChangeType recipe to analyzer rules."""
        recipe = """---
recipeList:
  - org.openrewrite.java.ChangeType:
      oldFullyQualifiedTypeName: org.junit.Assert
      newFullyQualifiedTypeName: org.junit.jupiter.api.Assertions
"""

        # Mock LLM
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[{
                "source_pattern": "org.junit.Assert",
                "target_pattern": "org.junit.jupiter.api.Assertions",
                "source_fqn": "org.junit.Assert",
                "location_type": "TYPE",
                "complexity": "LOW",
                "category": "api",
                "concern": "testing",
                "rationale": "JUnit 4 Assert class replaced with JUnit 5 Assertions",
                "example_before": "import org.junit.Assert;",
                "example_after": "import org.junit.jupiter.api.Assertions;"
            }]""",
                "usage": {"prompt_tokens": 120, "completion_tokens": 60, "total_tokens": 180},
            }
        )

        # Convert
        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator(source_framework="junit-4", target_framework="junit-5")

        recipe_content = ingester.ingest(recipe)
        patterns = extractor.extract_patterns(recipe_content)
        rules = generator.generate_rules(patterns)

        # Verify - should use TYPE location (not IMPORT)
        assert len(patterns) == 1
        assert patterns[0].source_fqn == "org.junit.Assert"
        assert patterns[0].location_type.value == "TYPE"

        assert len(rules) == 1
        assert rules[0].when["java.referenced"]["location"] == "TYPE"


@pytest.mark.integration
class TestOpenRewriteChangeDependency:
    """Test ChangeDependency recipe conversion."""

    def test_change_dependency_to_rules(self):
        """Should convert ChangeDependency recipe to analyzer rules."""
        recipe = """---
recipeList:
  - org.openrewrite.java.dependencies.ChangeDependency:
      oldGroupId: junit
      oldArtifactId: junit
      newGroupId: org.junit.jupiter
      newArtifactId: junit-jupiter-api
      newVersion: 5.9.0
"""

        # Mock LLM
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[{
                "source_pattern": "junit:junit",
                "target_pattern": "org.junit.jupiter:junit-jupiter-api:5.9.0",
                "complexity": "TRIVIAL",
                "category": "dependency",
                "concern": "testing",
                "rationale": "Dependency upgraded from JUnit 4 to JUnit 5"
            }]""",
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
        )

        # Convert
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator()

        patterns = extractor.extract_patterns(recipe)

        # Verify - dependency patterns don't generate rules (they're informational)
        assert len(patterns) == 1
        assert patterns[0].category == "dependency"
        assert "junit" in patterns[0].source_pattern


@pytest.mark.integration
class TestOpenRewriteCompositeRecipes:
    """Test composite recipes with multiple transformations."""

    def test_composite_recipe_to_multiple_rules(self):
        """Should convert composite recipe with multiple sub-recipes to multiple rules."""
        recipe = """---
name: com.example.SpringBoot3to4
displayName: Spring Boot 3 to 4 Migration
recipeList:
  - org.openrewrite.java.ChangePackage:
      oldPackageName: javax.servlet
      newPackageName: jakarta.servlet
  - org.openrewrite.java.ChangeType:
      oldFullyQualifiedTypeName: javax.security.cert.Certificate
      newFullyQualifiedTypeName: java.security.cert.Certificate
  - org.openrewrite.java.dependencies.ChangeDependency:
      oldGroupId: javax.servlet
      oldArtifactId: javax.servlet-api
      newGroupId: jakarta.servlet
      newArtifactId: jakarta.servlet-api
      newVersion: 5.0.0
"""

        # Mock LLM - returns multiple patterns
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[
                {
                    "source_pattern": "javax.servlet",
                    "target_pattern": "jakarta.servlet",
                    "source_fqn": "javax.servlet.*",
                    "location_type": "TYPE",
                    "complexity": "TRIVIAL",
                    "category": "api",
                    "concern": "jakarta-migration",
                    "rationale": "Package renamed"
                },
                {
                    "source_pattern": "javax.security.cert.Certificate",
                    "target_pattern": "java.security.cert.Certificate",
                    "source_fqn": "javax.security.cert.Certificate",
                    "location_type": "TYPE",
                    "complexity": "TRIVIAL",
                    "category": "api",
                    "concern": "security",
                    "rationale": "Type changed"
                },
                {
                    "source_pattern": "javax.servlet:javax.servlet-api",
                    "target_pattern": "jakarta.servlet:jakarta.servlet-api:5.0.0",
                    "complexity": "TRIVIAL",
                    "category": "dependency",
                    "concern": "jakarta-migration",
                    "rationale": "Dependency changed"
                }
            ]""",
                "usage": {"prompt_tokens": 250, "completion_tokens": 125, "total_tokens": 375},
            }
        )

        # Convert
        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator(
            source_framework="spring-boot-3", target_framework="spring-boot-4"
        )

        recipe_content = ingester.ingest(recipe)
        patterns = extractor.extract_patterns(recipe_content)
        rules = generator.generate_rules(patterns)

        # Should extract all 3 transformations
        assert len(patterns) == 3

        # Should generate 2 rules (2 API changes, dependency is informational)
        assert len(rules) == 2

        # Verify rule IDs are sequential
        assert rules[0].ruleID.endswith("-00000")
        assert rules[1].ruleID.endswith("-00010")

    def test_composite_recipe_groups_by_concern(self):
        """Should group rules by concern when processing composite recipes."""
        recipe = """---
recipeList:
  - org.openrewrite.java.ChangePackage:
      oldPackageName: javax.servlet
      newPackageName: jakarta.servlet
  - org.openrewrite.java.ChangePackage:
      oldPackageName: javax.security.cert
      newPackageName: java.security.cert
"""

        # Mock LLM
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[
                {
                    "source_pattern": "javax.servlet",
                    "target_pattern": "jakarta.servlet",
                    "source_fqn": "javax.servlet.*",
                    "location_type": "TYPE",
                    "complexity": "TRIVIAL",
                    "category": "api",
                    "concern": "jakarta-migration",
                    "rationale": "Package change"
                },
                {
                    "source_pattern": "javax.security.cert",
                    "target_pattern": "java.security.cert",
                    "source_fqn": "javax.security.cert.*",
                    "location_type": "TYPE",
                    "complexity": "TRIVIAL",
                    "category": "api",
                    "concern": "security",
                    "rationale": "Security package change"
                }
            ]""",
                "usage": {"prompt_tokens": 200, "completion_tokens": 100, "total_tokens": 300},
            }
        )

        # Convert
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator()

        patterns = extractor.extract_patterns(recipe)
        rules_by_concern = generator.generate_rules_by_concern(patterns)

        # Should group by concern
        assert "jakarta-migration" in rules_by_concern
        assert "security" in rules_by_concern
        assert len(rules_by_concern["jakarta-migration"]) == 1
        assert len(rules_by_concern["security"]) == 1


@pytest.mark.integration
class TestOpenRewriteYAMLExport:
    """Test exporting OpenRewrite-derived rules to YAML."""

    def test_export_openrewrite_rules_to_yaml(self, tmp_path):
        """Should export OpenRewrite-derived rules to valid YAML."""
        recipe = """---
recipeList:
  - org.openrewrite.java.ChangePackage:
      oldPackageName: old.package
      newPackageName: new.package
"""

        # Mock LLM
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": """[{
                "source_pattern": "old.package",
                "target_pattern": "new.package",
                "source_fqn": "old.package.*",
                "location_type": "TYPE",
                "complexity": "TRIVIAL",
                "category": "api",
                "rationale": "Package renamed"
            }]""",
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            }
        )

        # Convert
        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        generator = AnalyzerRuleGenerator(source_framework="test-1", target_framework="test-2")

        recipe_content = ingester.ingest(recipe)
        patterns = extractor.extract_patterns(recipe_content)
        rules = generator.generate_rules(patterns)

        # Export to YAML
        output_file = tmp_path / "openrewrite-rules.yaml"
        ruleset_dict = {
            "rules": [rule.model_dump(mode='json', exclude_none=True) for rule in rules]
        }

        with open(output_file, 'w') as f:
            yaml.dump(ruleset_dict, f, default_flow_style=False, sort_keys=False)

        # Verify YAML is valid and loadable
        assert output_file.exists()
        with open(output_file, 'r') as f:
            loaded = yaml.safe_load(f)

        assert "rules" in loaded
        assert len(loaded["rules"]) == 1
        assert loaded["rules"][0]["ruleID"] == "test-1-to-test-2-00000"
        assert "java.referenced" in loaded["rules"][0]["when"]


@pytest.mark.integration
class TestOpenRewriteErrorHandling:
    """Test error handling in OpenRewrite conversion."""

    def test_malformed_yaml_recipe(self):
        """Should handle malformed YAML gracefully."""
        malformed = "recipeList:\n  - invalid: {{{not valid yaml"

        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": "[]",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )

        ingester = GuideIngester()
        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)

        # Should not crash
        content = ingester.ingest(malformed)
        patterns = extractor.extract_patterns(content or "")

        # Should return empty patterns
        assert isinstance(patterns, list)

    def test_empty_recipe(self):
        """Should handle empty recipe."""
        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": "[]",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )

        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        patterns = extractor.extract_patterns("")

        assert patterns == []

    def test_recipe_with_no_applicable_transformations(self):
        """Should handle recipes with non-extractable transformations."""
        recipe = """---
recipeList:
  - org.openrewrite.java.format.AutoFormat
  - org.openrewrite.java.cleanup.CommonStaticAnalysis
"""

        mock_llm = Mock()
        mock_llm.generate = Mock(
            return_value={
                "response": "[]",
                "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60},
            }
        )

        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        patterns = extractor.extract_patterns(recipe)

        # LLM returns empty for non-extractable recipes
        assert isinstance(patterns, list)

    def test_llm_error_during_openrewrite_conversion(self):
        """Should handle LLM errors during OpenRewrite conversion."""
        recipe = """---
recipeList:
  - org.openrewrite.java.ChangePackage:
      oldPackageName: test.old
      newPackageName: test.new
"""

        # Mock LLM that fails
        mock_llm = Mock()
        mock_llm.generate = Mock(side_effect=Exception("LLM API error"))

        extractor = MigrationPatternExtractor(mock_llm, from_openrewrite=True)
        patterns = extractor.extract_patterns(recipe)

        # Should return empty instead of crashing
        assert patterns == []
