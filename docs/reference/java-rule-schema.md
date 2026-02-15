# Java Provider Rule Schema Design

## Konveyor Rule Structure

### Required Fields
- `ruleID`: Unique identifier (e.g., `applet-removal-00001`)
- `description`: Short summary of the issue
- `message`: Detailed explanation for developers
- `category`: Rule severity (`mandatory`, `optional`, `potential`)
- `effort`: Estimated remediation effort (1-13)
- `labels`: Array of tags (e.g., `["konveyor.io/target=openjdk21"]`)
- `when`: Condition block defining what to detect

### Condition Types for Java Provider

#### 1. Type Reference Detection
Detects usage of a specific class/interface:
```yaml
when:
  java.referenced:
    location: TYPE
    pattern: java.applet.Applet
```

#### 2. Package Detection
Detects usage of classes from specific packages:
```yaml
when:
  java.referenced:
    location: PACKAGE
    pattern: java.applet*
```

**Note**: When using wildcards with package patterns, the asterisk must NOT immediately follow a dot. Use `java.applet*` instead of `java.applet.*`.

#### 3. Inheritance Detection
Detects classes extending/implementing:
```yaml
when:
  java.referenced:
    location: INHERITANCE
    pattern: javax.swing.JApplet
```

#### 4. Method Call Detection
Detects calls to specific methods:
```yaml
when:
  java.referenced:
    location: METHOD_CALL
    pattern: java.applet.Applet.init()
```

#### 5. Constructor Call Detection
Detects instantiation of classes:
```yaml
when:
  java.referenced:
    location: CONSTRUCTOR_CALL
    pattern: java.applet.Applet
```

#### 6. Import Statement Detection
Detects specific import statements:
```yaml
when:
  java.referenced:
    location: IMPORT
    pattern: java.applet.Applet
```

**Note**: For IMPORT location, use specific class names, not package wildcards.

#### 7. Implements Type Detection
Detects types implementing specific interfaces:
```yaml
when:
  java.referenced:
    location: IMPLEMENTS_TYPE
    pattern: java.io.Serializable
```

#### 8. Enum Constant Detection
Detects references to enum constants:
```yaml
when:
  java.referenced:
    location: ENUM_CONSTANT
    pattern: java.time.temporal.ChronoUnit.DAYS
```

#### 9. Return Type Detection
Detects method return types:
```yaml
when:
  java.referenced:
    location: RETURN_TYPE
    pattern: java.lang.String
```

#### 10. Variable Declaration Detection
Detects variable type declarations:
```yaml
when:
  java.referenced:
    location: VARIABLE_DECLARATION
    pattern: java.util.Date
```

#### 11. Field Declaration Detection
Detects field declarations (can include annotation matching):
```yaml
when:
  java.referenced:
    location: FIELD
    pattern: java.lang.String
```

#### 12. Method Declaration Detection
Detects method declarations (can include annotation matching):
```yaml
when:
  java.referenced:
    location: METHOD
    pattern: javax.ejb.Stateless
```

#### 13. Class Declaration Detection
Detects class declarations (can include annotation matching):
```yaml
when:
  java.referenced:
    location: CLASS
    pattern: javax.persistence.Entity
```

## Pattern Syntax Rules

The Java provider uses [Eclipse JDT SearchPattern](https://help.eclipse.org/latest/topic/org.eclipse.jdt.doc.isv/reference/api/org/eclipse/jdt/core/search/SearchPattern.html) syntax.

### Wildcard Rules

- `*` matches any sequence of characters
- **CRITICAL**: The asterisk wildcard must NOT be placed immediately after a dot (`.`) for package patterns
  - ✅ **Correct**: `javax.xml*` (matches `javax.xml`, `javax.xml.bind`, etc.)
  - ❌ **Incorrect**: `javax.xml.*` (invalid syntax)

### Method Pattern Syntax

For method patterns, you can specify return types and signatures:

```yaml
# Match any method returning String
when:
  java.referenced:
    location: METHOD_CALL
    pattern: "* java.lang.String"

# Match specific method signature
when:
  java.referenced:
    location: METHOD_CALL
    pattern: "org.konveyor.MyClass.method(*) java.util.List<? extends java.lang.String>"
```

**Known Limitation**: Fully qualified static method matching is prone to errors in the analyzer.

### Pattern Match Types

Eclipse JDT SearchPattern supports:
- **Exact match**: Full qualified name without wildcards
- **Prefix match**: Pattern ending with `*`
- **Pattern match**: Pattern containing `*` wildcards
- **Regexp match**: Regular expression patterns (advanced usage)

### Best Practices

1. **For PACKAGE location**: Use patterns like `java.applet*` (no dot before asterisk)
2. **For IMPORT location**: Use specific class names like `java.applet.Applet`
3. **For TYPE/CLASS location**: Use fully qualified names or wildcards
4. **For METHOD_CALL**: Include return type when disambiguation is needed

## Input Schema for Generator

To generate rules for removed APIs, the generator should accept:

```json
{
  "migration": {
    "name": "JDK 21 Applet API Removal",
    "source": "openjdk17",
    "target": "openjdk21",
    "guide_url": "https://openjdk.org/jeps/504"
  },
  "removals": [
    {
      "type": "class",
      "fqn": "java.applet.Applet",
      "category": "mandatory",
      "effort": 5,
      "message": "The Applet API has been removed in JDK 21. Consider migrating to Java Web Start or browser-based alternatives."
    },
    {
      "type": "class",
      "fqn": "javax.swing.JApplet",
      "category": "mandatory",
      "effort": 5,
      "message": "JApplet has been removed in JDK 21. Consider migrating to JFrame or JPanel for Swing applications."
    }
  ]
}
```

## Rule Generation Strategy

For each removed class, generate multiple rules to catch different usage patterns:

1. **Import detection** - Catches `import java.applet.Applet;`
2. **Type reference** - Catches variable declarations, parameters, etc.
3. **Inheritance** - Catches `extends Applet` or `implements AppletContext`
4. **Constructor calls** - Catches `new Applet()`
5. **Method calls** - Catches calls to removed methods

## Example Generated Rule

```yaml
- ruleID: applet-removal-00001
  description: "java.applet.Applet usage detected"
  message: "The Applet API has been removed in JDK 21. Consider migrating to Java Web Start or browser-based alternatives."
  category: mandatory
  effort: 5
  labels:
    - konveyor.io/source=openjdk17
    - konveyor.io/target=openjdk21+
  links:
    - title: "JEP 504: Remove the Applet API"
      url: "https://openjdk.org/jeps/504"
  when:
    or:
      - java.referenced:
          location: IMPORT
          pattern: java.applet.Applet
      - java.referenced:
          location: INHERITANCE
          pattern: java.applet.Applet
      - java.referenced:
          location: TYPE
          pattern: java.applet.Applet
      - java.referenced:
          location: CONSTRUCTOR_CALL
          pattern: java.applet.Applet
```
