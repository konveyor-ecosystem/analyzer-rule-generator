"""
Condition builder utilities for generating analyzer rule conditions.

This module provides helper functions to build various types of conditions
for Konveyor analyzer rules, reducing code duplication in the generator.
"""

from typing import Any, Dict, List, Optional


def build_or_condition_with_alternatives(
    base_condition: Dict[str, Any],
    alternative_patterns: List[str],
    condition_key: str,
    pattern_key: str = "pattern",
    additional_keys: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build an OR condition with a base pattern and alternatives.

    This helper eliminates duplication when building conditions that support
    alternative patterns (e.g., javax vs jakarta, old vs relocated Maven coords).

    Args:
        base_condition: The base condition dict (e.g., {"java.referenced": {...}})
        alternative_patterns: List of alternative pattern values
        condition_key: The condition type (e.g., "java.referenced", "java.dependency")
        pattern_key: The key for the pattern value (default: "pattern")
        additional_keys: Additional keys to include in each condition (e.g., {"location": "TYPE"})

    Returns:
        OR condition dict with all patterns

    Examples:
        >>> build_or_condition_with_alternatives(
        ...     {"java.referenced": {"pattern": "javax.ejb.Stateless", "location": "ANNOTATION"}},
        ...     ["jakarta.ejb.Stateless"],
        ...     "java.referenced",
        ...     additional_keys={"location": "ANNOTATION"}
        ... )
        {
            "or": [
                {"java.referenced": {"pattern": "javax.ejb.Stateless", "location": "ANNOTATION"}},
                {"java.referenced": {"pattern": "jakarta.ejb.Stateless", "location": "ANNOTATION"}}
            ]
        }
    """
    if not alternative_patterns:
        return base_condition

    conditions = [base_condition]

    for alt_pattern in alternative_patterns:
        alt_condition = {condition_key: {pattern_key: alt_pattern}}

        # Add any additional keys (like location, lowerbound, etc.)
        if additional_keys:
            alt_condition[condition_key].update(additional_keys)

        conditions.append(alt_condition)

    return {"or": conditions}


def build_builtin_condition(pattern: str, file_pattern: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a builtin.filecontent condition.

    Args:
        pattern: Regex pattern to match
        file_pattern: Optional file pattern regex to filter files

    Returns:
        Builtin condition dict

    Examples:
        >>> build_builtin_condition("ReactDOM\\.render\\(", "\\.(j|t)sx?$")
        {
            "builtin.filecontent": {
                "pattern": "ReactDOM\\.render\\(",
                "filePattern": "\\.(j|t)sx?$"
            }
        }
    """
    condition = {"builtin.filecontent": {"pattern": pattern}}

    if file_pattern:
        condition["builtin.filecontent"]["filePattern"] = file_pattern

    return condition


def build_nodejs_condition(pattern: str) -> Dict[str, Any]:
    """
    Build a nodejs.referenced condition.

    Args:
        pattern: Symbol name to find (class, function, type, etc.)

    Returns:
        Nodejs condition dict

    Examples:
        >>> build_nodejs_condition("ComponentFactoryResolver")
        {"nodejs.referenced": {"pattern": "ComponentFactoryResolver"}}
    """
    return {"nodejs.referenced": {"pattern": pattern}}


def build_csharp_condition(pattern: str, location: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a c-sharp.referenced condition.

    Args:
        pattern: FQN or pattern to find
        location: Optional location type (FIELD, CLASS, METHOD, ALL)

    Returns:
        C# condition dict

    Examples:
        >>> build_csharp_condition("System.Web.Http", "ALL")
        {
            "c-sharp.referenced": {
                "pattern": "System.Web.Http",
                "location": "ALL"
            }
        }
    """
    condition = {"c-sharp.referenced": {"pattern": pattern}}

    if location:
        condition["c-sharp.referenced"]["location"] = location

    return condition


def build_java_referenced_condition(
    pattern: str, location: str, alternative_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Build a java.referenced condition with optional alternatives.

    Args:
        pattern: FQN to find
        location: Location type (IMPORT, TYPE, METHOD_CALL, etc.)
        alternative_patterns: Optional list of alternative FQNs

    Returns:
        Java referenced condition (simple or OR with alternatives)

    Examples:
        >>> build_java_referenced_condition(
        ...     "javax.ejb.Stateless",
        ...     "ANNOTATION",
        ...     ["jakarta.ejb.Stateless"]
        ... )
        {
            "or": [
                {"java.referenced": {"pattern": "javax.ejb.Stateless", "location": "ANNOTATION"}},
                {"java.referenced": {"pattern": "jakarta.ejb.Stateless", "location": "ANNOTATION"}}
            ]
        }
    """
    base_condition = {"java.referenced": {"pattern": pattern, "location": location}}

    if alternative_patterns:
        return build_or_condition_with_alternatives(
            base_condition,
            alternative_patterns,
            "java.referenced",
            additional_keys={"location": location},
        )

    return base_condition


def build_go_referenced_condition(
    pattern: str, location: str = None, alternative_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Build a go.referenced condition with optional alternatives.

    Args:
        pattern: Symbol/package to find (e.g., "bytes.Title", "net/http")
        location: Deprecated parameter, no longer used (go provider doesn't support location)
        alternative_patterns: Optional list of alternative patterns

    Returns:
        Go referenced condition (simple or OR with alternatives)

    Examples:
        >>> build_go_referenced_condition("bytes.Title")
        {"go.referenced": {"pattern": "bytes.Title"}}
    """
    base_condition = {"go.referenced": {"pattern": pattern}}

    if alternative_patterns:
        return build_or_condition_with_alternatives(
            base_condition,
            alternative_patterns,
            "go.referenced",
        )

    return base_condition


def build_java_dependency_condition(
    dependency_name: str, alternative_names: Optional[List[str]] = None, lowerbound: str = "0.0.0"
) -> Dict[str, Any]:
    """
    Build a java.dependency condition with optional alternatives.

    Args:
        dependency_name: Maven dependency name (groupId.artifactId format)
        alternative_names: Optional list of alternative dependency names
        lowerbound: Version lowerbound (default: "0.0.0" for any version)

    Returns:
        Java dependency condition (simple or OR with alternatives)

    Examples:
        >>> build_java_dependency_condition(
        ...     "mysql.mysql-connector-java",
        ...     ["com.mysql.mysql-connector-j"]
        ... )
        {
            "or": [
                {"java.dependency": {"name": "mysql.mysql-connector-java", "lowerbound": "0.0.0"}},
                {"java.dependency": {"name": "com.mysql.mysql-connector-j", "lowerbound": "0.0.0"}}
            ]
        }
    """
    base_condition = {"java.dependency": {"name": dependency_name, "lowerbound": lowerbound}}

    if alternative_names:
        return build_or_condition_with_alternatives(
            base_condition,
            alternative_names,
            "java.dependency",
            pattern_key="name",
            additional_keys={"lowerbound": lowerbound},
        )

    return base_condition


def build_combo_condition(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build an AND condition combining multiple conditions.

    Args:
        conditions: List of condition dicts to combine with AND

    Returns:
        AND condition dict

    Examples:
        >>> build_combo_condition([
        ...     {"nodejs.referenced": {"pattern": "Button"}},
        ...     {"builtin.filecontent": {"pattern": "<Button[^>]*\\bisActive\\b"}}
        ... ])
        {
            "and": [
                {"nodejs.referenced": {"pattern": "Button"}},
                {"builtin.filecontent": {"pattern": "<Button[^>]*\\bisActive\\b"}}
            ]
        }
    """
    return {"and": conditions}
