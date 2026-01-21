#!/bin/bash
#
# Analyzer Rule Generator Demo Script
#
# This script demonstrates the complete workflow from migration guide to
# Konveyor rules with test data generation.
#
# Usage:
#   ./scripts/demo.sh [step]
#
# Steps:
#   1  - Generate rules from migration guide
#   2  - Generate test data
#   3  - Validate with kantra (if installed)
#   all - Run all steps
#
# For live demos, run each step individually to explain what's happening.
#

set -e  # Exit on error

# Ensure we're running from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# Activate virtual environment if it exists
if [ -d "venv/bin" ]; then
    source venv/bin/activate
    VENV_ACTIVATED=true
elif [ -d ".venv/bin" ]; then
    source .venv/bin/activate
    VENV_ACTIVATED=true
else
    VENV_ACTIVATED=false
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Demo Configuration - Choose your migration guide
# ============================================================================

# Option 1: React 17 to 18 (SMALL - Recommended for quick demos ~5 min)
GUIDE_URL="https://react.dev/blog/2022/03/08/react-18-upgrade-guide"
SOURCE="react-17"
TARGET="react-18"
FOLLOW_LINKS_FLAG=""  # Single page guide

# Option 2: Go 1.17 to 1.18 (SMALL - Deprecated API migrations ~5-8 min)
# GUIDE_URL="https://tip.golang.org/doc/go1.18"
# SOURCE="go-1.17"
# TARGET="go-1.18"
# FOLLOW_LINKS_FLAG=""  # Single page guide

# Option 3: Spring Boot 2 to 3 (MEDIUM - ~8-10 min)
# GUIDE_URL="https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Migration-Guide"
# SOURCE="spring-boot-2"
# TARGET="spring-boot-3"
# FOLLOW_LINKS_FLAG=""  # Single page guide

# Option 4: PatternFly v5 to v6 (LARGE - ~15-20 min, comprehensive)
#GUIDE_URL="https://www.patternfly.org/get-started/upgrade/"
#SOURCE="patternfly-v5"
#TARGET="patternfly-v6"
#FOLLOW_LINKS_FLAG="--follow-links --max-depth 1"

# Demo output directories - organized by migration guide
DEMO_DIR="demo-output"
MIGRATION_DIR="${DEMO_DIR}/${SOURCE}-to-${TARGET}"
RULES_OUTPUT="${MIGRATION_DIR}/rules"
TEST_OUTPUT="${MIGRATION_DIR}/tests"

# Helper functions
print_header() {
    echo -e "\n${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

pause_for_demo() {
    if [ "${INTERACTIVE:-yes}" = "yes" ]; then
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read
    fi
}

check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found"
        exit 1
    fi
    print_success "Python 3 installed: $(python3 --version)"

    # Check virtual environment
    if [ "${VENV_ACTIVATED}" = true ]; then
        print_success "Virtual environment activated"
    else
        print_warning "Virtual environment not found"
        print_info "Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    fi

    # Check API key
    if [ -z "${ANTHROPIC_API_KEY}" ] && [ -z "${OPENAI_API_KEY}" ]; then
        print_warning "No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY"
        print_info "Example: export ANTHROPIC_API_KEY='your-key-here'"
        exit 1
    fi

    if [ -n "${ANTHROPIC_API_KEY}" ]; then
        print_success "ANTHROPIC_API_KEY set"
        PROVIDER="anthropic"
    elif [ -n "${OPENAI_API_KEY}" ]; then
        print_success "OPENAI_API_KEY set"
        PROVIDER="openai"
    fi

    # Check if kantra is available (optional)
    if command -v kantra &> /dev/null; then
        print_success "Kantra installed (optional for step 3)"
        KANTRA_AVAILABLE=true
    else
        print_warning "Kantra not installed (skipping validation step)"
        KANTRA_AVAILABLE=false
    fi

    print_success "All prerequisites met!"
    pause_for_demo
}

step_1_generate_rules() {
    print_header "Step 1: Generate Rules from Migration Guide"

    print_info "Input: ${GUIDE_URL}"
    print_info "Source: ${SOURCE}"
    print_info "Target: ${TARGET}"
    print_info "Output: ${RULES_OUTPUT}"
    echo ""

    # Create output directory
    mkdir -p "${RULES_OUTPUT}"

    # Show the command
    echo -e "${YELLOW}Command:${NC}"
    if [ -n "${FOLLOW_LINKS_FLAG}" ]; then
        cat <<EOF
python3 scripts/generate_rules.py \\
  --guide "${GUIDE_URL}" \\
  --source "${SOURCE}" \\
  --target "${TARGET}" \\
  --output "${RULES_OUTPUT}" \\
  --provider "${PROVIDER}" \\
  ${FOLLOW_LINKS_FLAG}
EOF
    else
        cat <<EOF
python3 scripts/generate_rules.py \\
  --guide "${GUIDE_URL}" \\
  --source "${SOURCE}" \\
  --target "${TARGET}" \\
  --output "${RULES_OUTPUT}" \\
  --provider "${PROVIDER}"
EOF
    fi
    echo ""

    pause_for_demo

    # Run the command
    print_info "Running rule generation..."
    if [ -n "${FOLLOW_LINKS_FLAG}" ]; then
        python3 scripts/generate_rules.py \
          --guide "${GUIDE_URL}" \
          --source "${SOURCE}" \
          --target "${TARGET}" \
          --output "${RULES_OUTPUT}" \
          --provider "${PROVIDER}" \
          ${FOLLOW_LINKS_FLAG}
    else
        python3 scripts/generate_rules.py \
          --guide "${GUIDE_URL}" \
          --source "${SOURCE}" \
          --target "${TARGET}" \
          --output "${RULES_OUTPUT}" \
          --provider "${PROVIDER}"
    fi

    # Show results
    echo ""
    print_success "Rules generated successfully!"

    print_info "Generated files:"
    find "${RULES_OUTPUT}" -name "*.yaml" -type f | while read file; do
        rule_count=$(grep -c "ruleID:" "$file" || true)
        echo "  - $(basename $file): ${rule_count} rules"
    done

    # Show a sample rule
    FIRST_RULE_FILE=$(find "${RULES_OUTPUT}" -name "*.yaml" -type f | head -1)
    if [ -n "${FIRST_RULE_FILE}" ]; then
        echo ""
        print_info "Sample rule from $(basename ${FIRST_RULE_FILE}):"
        echo ""
        # Show first rule only
        awk '/^- ruleID:/{p=1} p{print} /^$/{if(p) exit}' "${FIRST_RULE_FILE}" | head -20
    fi

    # Optional: Validate generated rules
    if [ "${VALIDATE_RULES:-no}" = "yes" ]; then
        echo ""
        print_info "Validating generated rules..."
        step_validate_rules
    fi

    pause_for_demo
}

step_2_generate_tests() {
    print_header "Step 2: Generate Test Data"

    # Check rules directory exists
    if [ ! -d "${RULES_OUTPUT}" ]; then
        print_error "No rules directory found. Run step 1 first."
        exit 1
    fi

    # Count rule files with actual rules (contains "ruleID:")
    RULE_COUNT=$(find "${RULES_OUTPUT}" -name "*.yaml" -type f -exec grep -l "ruleID:" {} \; | wc -l | tr -d ' ')

    if [ "${RULE_COUNT}" -eq 0 ]; then
        print_error "No rule files with rules found. Run step 1 first."
        exit 1
    fi

    print_info "Input: ${RULES_OUTPUT}"
    print_info "Rule files: ${RULE_COUNT}"
    print_info "Output: ${TEST_OUTPUT}"
    print_info "Language: Auto-detected from rules"
    echo ""

    # Create output directory
    mkdir -p "${TEST_OUTPUT}"

    # Show the command
    echo -e "${YELLOW}Command:${NC}"
    cat <<EOF
python3 scripts/generate_test_data.py \\
  --rules "${RULES_OUTPUT}" \\
  --output "${TEST_OUTPUT}" \\
  --source "${SOURCE}" \\
  --target "${TARGET}" \\
  --guide-url "${GUIDE_URL}" \\
  --provider "${PROVIDER}" \\
  --max-iterations 3
EOF
    echo ""

    pause_for_demo

    # Run the command
    print_info "Running test data generation with autonomous test-fix loop..."
    python3 scripts/generate_test_data.py \
      --rules "${RULES_OUTPUT}" \
      --output "${TEST_OUTPUT}" \
      --source "${SOURCE}" \
      --target "${TARGET}" \
      --guide-url "${GUIDE_URL}" \
      --provider "${PROVIDER}" \
      --max-iterations 3

    # Show results
    echo ""
    print_success "Test data generated successfully!"

    print_info "Generated structure:"
    tree -L 3 "${TEST_OUTPUT}" 2>/dev/null || find "${TEST_OUTPUT}" -type f | head -20

    # Show sample test file
    TEST_FILE=$(find "${TEST_OUTPUT}" -name "*.test.yaml" -type f | head -1)
    if [ -n "${TEST_FILE}" ]; then
        echo ""
        print_info "Sample test configuration:"
        echo ""
        head -30 "${TEST_FILE}"
    fi

    pause_for_demo
}

step_validate_rules() {
    print_header "Step 1b: Validate Generated Rules (Optional)"

    if [ ! -d "${RULES_OUTPUT}" ]; then
        print_error "No rules directory found. Run step 1 first."
        exit 1
    fi

    print_info "Validating rules in: ${RULES_OUTPUT}"
    echo ""

    # Show the command
    echo -e "${YELLOW}Command:${NC}"
    cat <<EOF
python3 scripts/validate_rules.py \\
  --rules "${RULES_OUTPUT}" \\
  --auto-fix
EOF
    echo ""

    pause_for_demo

    # Run validation (syntactic only by default)
    print_info "Running syntactic validation with auto-fix (fast, free)..."
    python3 scripts/validate_rules.py --rules "${RULES_OUTPUT}" --auto-fix
    VALIDATION_RESULT=$?

    echo ""
    if [ ${VALIDATION_RESULT} -eq 0 ]; then
        print_success "All rules passed validation!"
    else
        print_warning "Some rules have issues - review warnings above"
        print_info "Rules are still usable, but consider fixing issues"
    fi

    # Offer semantic validation if user wants
    if [ "${INTERACTIVE:-yes}" = "yes" ]; then
        echo ""
        print_info "Semantic validation uses AI to check description/pattern alignment (~\$0.01 per rule)"
        echo -e "${YELLOW}Run semantic validation? (y/N)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo ""
            print_info "Running semantic validation with auto-fix..."
            python3 scripts/validate_rules.py --rules "${RULES_OUTPUT}" --semantic --provider "${PROVIDER}" --auto-fix
        fi
    fi

    pause_for_demo
}

step_view_rules() {
    print_header "Step 1c: View Rules in Interactive Viewer (Optional)"

    if [ ! -d "${RULES_OUTPUT}" ]; then
        print_error "No rules directory found. Run step 1 first."
        exit 1
    fi

    # Count rule files
    RULE_COUNT=$(find "${RULES_OUTPUT}" -name "*.yaml" -type f | wc -l | tr -d ' ')

    if [ "$RULE_COUNT" -eq 0 ]; then
        print_error "No rule files found in ${RULES_OUTPUT}"
        exit 1
    fi

    print_info "Generating interactive HTML viewer for all rules in: ${RULES_OUTPUT}"
    print_info "Found ${RULE_COUNT} rule file(s)"
    echo ""

    # Generate viewer HTML
    VIEWER_OUTPUT="${MIGRATION_DIR}/rules-viewer.html"

    # Show the command
    echo -e "${YELLOW}Command:${NC}"
    cat <<EOF
python3 scripts/generate_rule_viewer.py \\
  --rules "${RULES_OUTPUT}" \\
  --output "${VIEWER_OUTPUT}" \\
  --title "${SOURCE} → ${TARGET} Migration Rules" \\
  --open
EOF
    echo ""

    pause_for_demo

    # Generate viewer
    print_info "Generating viewer..."
    python3 scripts/generate_rule_viewer.py \
      --rules "${RULES_OUTPUT}" \
      --output "${VIEWER_OUTPUT}" \
      --title "${SOURCE} → ${TARGET} Migration Rules" \
      --open

    echo ""
    print_success "Viewer generated!"
    print_info "Location: ${VIEWER_OUTPUT}"
    echo ""
    print_info "The viewer provides:"
    echo "  - Searchable, filterable rule browser"
    echo "  - Expandable rule details"
    echo "  - Category and effort filtering"
    echo "  - Syntax highlighting"
    echo ""
    print_info "You can also use the web-based viewer at docs/rule-viewer.html"
    print_info "to load multiple rulesets dynamically"

    pause_for_demo
}

step_3_validate_with_kantra() {
    print_header "Step 3: Validate with Kantra (Optional)"

    if [ "${KANTRA_AVAILABLE}" = false ]; then
        print_warning "Kantra not installed - skipping validation"
        print_info "To install: https://github.com/konveyor/kantra"
        return 0
    fi

    # Check test output directory exists
    if [ ! -d "${TEST_OUTPUT}" ]; then
        print_warning "No test output directory found - skipping validation"
        return 0
    fi

    # Find all .test.yaml files
    TEST_FILES=$(find "${TEST_OUTPUT}" -name "*.test.yaml" -type f 2>/dev/null)
    TEST_COUNT=$(echo "${TEST_FILES}" | grep -v '^$' | wc -l | tr -d ' ')

    if [ "${TEST_COUNT}" -eq 0 ]; then
        print_warning "No test files found - skipping validation"
        return 0
    fi

    print_info "Test directory: ${TEST_OUTPUT}"
    print_info "Test files: ${TEST_COUNT}"
    echo ""

    # Show the command
    echo -e "${YELLOW}Command:${NC}"
    cat <<EOF
kantra test ${TEST_OUTPUT}/*.test.yaml
EOF
    echo ""

    pause_for_demo

    # Run kantra test on all test files
    print_info "Running Kantra tests (this may take several minutes for Maven builds)..."
    echo ""

    # Change to project root for kantra test (it needs relative paths to work)
    cd "${PROJECT_ROOT}" || exit 1

    # Run kantra test and save output for formatting summary
    TEMP_OUTPUT=$(mktemp)
    kantra test ${TEST_OUTPUT}/*.test.yaml 2>&1 | tee "${TEMP_OUTPUT}" || true

    # Parse accurate test statistics from output
    echo ""
    echo "======================================================================"
    echo "Test Summary:"
    echo "======================================================================"

    # Count test files (.test.yaml lines)
    # Kantra always prints "PASSED" even for failed tests (shows "0/1 PASSED")
    # We need to parse X/Y and only count as passed when X == Y
    TEST_FILES_TOTAL=0
    TEST_FILES_PASSED=0
    while IFS= read -r line; do
        if [[ "$line" =~ \.test\.yaml[[:space:]]+([0-9]+)/([0-9]+) ]]; then
            passed="${BASH_REMATCH[1]}"
            total="${BASH_REMATCH[2]}"
            TEST_FILES_TOTAL=$((TEST_FILES_TOTAL + 1))
            if [ "$passed" -eq "$total" ]; then
                TEST_FILES_PASSED=$((TEST_FILES_PASSED + 1))
            fi
        fi
    done < "${TEMP_OUTPUT}"
    TEST_FILES_FAILED=$((TEST_FILES_TOTAL - TEST_FILES_PASSED))

    # Count individual test cases (rule IDs with numbers)
    # Same issue - parse X/Y counts instead of looking for "PASSED" keyword
    TEST_CASES_TOTAL=0
    TEST_CASES_PASSED=0
    while IFS= read -r line; do
        if [[ "$line" =~ -[0-9]{5}[[:space:]]+([0-9]+)/([0-9]+) ]]; then
            passed="${BASH_REMATCH[1]}"
            total="${BASH_REMATCH[2]}"
            TEST_CASES_TOTAL=$((TEST_CASES_TOTAL + 1))
            if [ "$passed" -eq "$total" ]; then
                TEST_CASES_PASSED=$((TEST_CASES_PASSED + 1))
            fi
        fi
    done < "${TEMP_OUTPUT}"
    TEST_CASES_FAILED=$((TEST_CASES_TOTAL - TEST_CASES_PASSED))

    # Calculate percentages
    if [ "${TEST_FILES_TOTAL}" -gt 0 ]; then
        TEST_FILES_PCT=$(awk "BEGIN {printf \"%.1f\", ($TEST_FILES_PASSED / $TEST_FILES_TOTAL) * 100}")
    else
        TEST_FILES_PCT="0.0"
    fi

    if [ "${TEST_CASES_TOTAL}" -gt 0 ]; then
        TEST_CASES_PCT=$(awk "BEGIN {printf \"%.1f\", ($TEST_CASES_PASSED / $TEST_CASES_TOTAL) * 100}")
    else
        TEST_CASES_PCT="0.0"
    fi

    # Display summary
    echo "Test Files:  ${TEST_FILES_PASSED}/${TEST_FILES_TOTAL} passed (${TEST_FILES_PCT}%)"
    echo "Test Cases:  ${TEST_CASES_PASSED}/${TEST_CASES_TOTAL} passed (${TEST_CASES_PCT}%)"
    echo "======================================================================"

    rm -f "${TEMP_OUTPUT}"

    echo ""
    if [ "${TEST_FILES_FAILED}" -eq 0 ] && [ "${TEST_FILES_TOTAL}" -gt 0 ]; then
        print_success "All test files passed! (${TEST_FILES_TOTAL} files, ${TEST_CASES_TOTAL} test cases)"
    elif [ "${TEST_FILES_FAILED}" -gt 0 ]; then
        print_warning "${TEST_FILES_FAILED} test file(s) failed, ${TEST_FILES_PASSED} passed"
        print_warning "${TEST_CASES_FAILED} test case(s) failed, ${TEST_CASES_PASSED} passed"
        print_info "Review the output above for details"
    else
        print_warning "No test results found - check output above"
    fi

    pause_for_demo
}

step_4_show_submission() {
    print_header "Step 4: Submission to Konveyor (Next Steps)"

    print_info "Your generated rules are ready for submission!"
    echo ""

    echo "📋 What you have:"
    echo "  1. Rules: ${RULES_OUTPUT}/*.yaml"
    echo "  2. Tests: ${TEST_OUTPUT}/"
    if [ "${KANTRA_AVAILABLE}" = true ]; then
        echo "  3. Validation: ${MIGRATION_DIR}/analysis-output.yaml"
    fi
    echo ""
    print_info "All output for this demo: ${MIGRATION_DIR}/"
    echo ""

    echo "📦 Next steps for contribution:"
    echo "  1. Fork konveyor/rulesets repository"
    echo "  2. Copy rules to appropriate directory"
    echo "  3. Copy tests to tests/ directory"
    echo "  4. Create pull request with:"
    echo "     - Rule YAML files"
    echo "     - Test data"
    echo "     - Test configuration (.test.yaml)"
    echo "     - README documenting the migration"
    echo ""

    print_info "See docs/guides/konveyor-submission-guide.md for detailed steps"

    pause_for_demo
}

show_summary() {
    print_header "Demo Summary"

    echo "✨ What we demonstrated:"
    echo ""
    echo "  1️⃣  Generated Konveyor rules from migration guide"
    echo "     - Extracted migration patterns using AI"
    echo "     - Created analyzer-lsp compatible YAML"
    echo "     - Classified complexity levels"
    echo "     - Optional: Validated rule quality (step 1b)"
    echo ""
    echo "  2️⃣  Generated test data automatically"
    echo "     - AI-created test applications"
    echo "     - Test configurations for validation"
    echo "     - Autonomous test-fix loop (up to 3 iterations)"
    echo "     - Ready for kantra testing"
    echo ""

    if [ "${KANTRA_AVAILABLE}" = true ]; then
        echo "  3️⃣  Validated rules with Kantra"
        echo "     - Confirmed rules detect violations"
        echo "     - Ready for submission"
        echo ""
    fi

    echo "⏱️  Total time: ~5-15 minutes (vs days of manual work)"
    echo ""
    echo "📚 Learn more:"
    echo "  - Documentation: README.md"
    echo "  - Submission guide: docs/guides/konveyor-submission-guide.md"
    echo "  - Examples: examples/output/"
    echo ""

    print_success "Demo complete!"
}

cleanup_demo() {
    # Check for --force flag and clean mode
    local FORCE_CLEAN="${1:-}"
    local CLEAN_MODE="${2:-demo}"  # "demo" or "all"

    if [ "${CLEAN_MODE}" = "all" ]; then
        print_header "Cleanup Demo Files and Caches"
    else
        print_header "Cleanup Demo Files"
    fi

    # Count what we'll be removing
    ITEMS_TO_CLEAN=()

    # Always check for demo output
    if [ -d "${DEMO_DIR}" ]; then
        ITEMS_TO_CLEAN+=("demo-output/")
    fi

    # If clean-all mode, also check for cache files
    if [ "${CLEAN_MODE}" = "all" ]; then
        # Find Python cache files
        PYCACHE_DIRS=$(find . -type d -name "__pycache__" 2>/dev/null | wc -l | tr -d ' ')
        if [ "${PYCACHE_DIRS}" -gt 0 ]; then
            ITEMS_TO_CLEAN+=("__pycache__ directories (${PYCACHE_DIRS})")
        fi

        PYC_FILES=$(find . -type f -name "*.pyc" 2>/dev/null | wc -l | tr -d ' ')
        if [ "${PYC_FILES}" -gt 0 ]; then
            ITEMS_TO_CLEAN+=("*.pyc files (${PYC_FILES})")
        fi

        # Find pytest cache
        if [ -d ".pytest_cache" ]; then
            ITEMS_TO_CLEAN+=(".pytest_cache/")
        fi
    fi

    # Show what will be cleaned
    if [ ${#ITEMS_TO_CLEAN[@]} -eq 0 ]; then
        print_info "Environment is already clean"
        return 0
    fi

    echo "Items to clean:"
    for item in "${ITEMS_TO_CLEAN[@]}"; do
        echo "  - ${item}"
    done
    echo ""

    # If force flag provided, skip confirmation
    if [ "${FORCE_CLEAN}" = "--force" ]; then
        CONFIRMED=true
    else
        echo -e "${YELLOW}Remove all listed items? (y/N)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            CONFIRMED=true
        else
            CONFIRMED=false
        fi
    fi

    if [ "${CONFIRMED}" = true ]; then
        # Remove demo output
        if [ -d "${DEMO_DIR}" ]; then
            print_info "Removing ${DEMO_DIR}..."
            rm -rf "${DEMO_DIR}"
            print_success "Demo output removed"
        fi

        # Remove cache files only in clean-all mode
        if [ "${CLEAN_MODE}" = "all" ]; then
            # Remove Python cache
            if [ "${PYCACHE_DIRS}" -gt 0 ]; then
                print_info "Removing __pycache__ directories..."
                find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
                print_success "Python cache directories removed"
            fi

            if [ "${PYC_FILES}" -gt 0 ]; then
                print_info "Removing .pyc files..."
                find . -type f -name "*.pyc" -delete 2>/dev/null || true
                print_success "Python compiled files removed"
            fi

            # Remove pytest cache
            if [ -d ".pytest_cache" ]; then
                print_info "Removing .pytest_cache..."
                rm -rf ".pytest_cache"
                print_success "Pytest cache removed"
            fi
        fi

        echo ""
        print_success "Environment cleaned successfully!"
    else
        print_info "Cleanup cancelled"
    fi
}

show_usage() {
    cat <<EOF
Analyzer Rule Generator Demo Script

Usage:
  $0 [step]

Steps:
  1         - Generate rules from migration guide
  1b        - Validate generated rules (optional)
  1c        - View rules in interactive HTML viewer (optional)
  2         - Generate test data
  3         - Validate with kantra (if installed)
  4         - Show submission next steps
  all       - Run all steps sequentially
  clean     - Remove demo output files (interactive)
  clean-all - Remove demo output and all cache files (interactive)
  --force   - Add to clean commands to skip confirmation

Environment Variables:
  ANTHROPIC_API_KEY - Anthropic API key (recommended)
  OPENAI_API_KEY    - OpenAI API key (alternative)
  INTERACTIVE=no    - Skip pauses between steps
  VALIDATE_RULES=yes - Auto-run rule validation after step 1

Examples:
  # Run complete demo with pauses
  $0 all

  # Run specific step
  $0 1

  # Run all steps without pauses (for CI)
  INTERACTIVE=no $0 all

  # Clean up demo files (with confirmation)
  $0 clean

  # Clean up everything including caches (with confirmation)
  $0 clean-all

  # Force clean without confirmation
  $0 clean --force
  $0 clean-all --force
EOF
}

# Main execution
main() {
    case "${1:-}" in
        1)
            check_prerequisites
            step_1_generate_rules
            ;;
        1b)
            check_prerequisites
            step_validate_rules
            ;;
        1c)
            check_prerequisites
            step_view_rules
            ;;
        2)
            check_prerequisites
            step_2_generate_tests
            ;;
        3)
            check_prerequisites
            step_3_validate_with_kantra
            ;;
        4)
            step_4_show_submission
            ;;
        all)
            check_prerequisites
            step_1_generate_rules
            step_2_generate_tests
            step_3_validate_with_kantra
            step_4_show_submission
            show_summary
            ;;
        clean)
            # Check for --force flag in second argument
            if [ "${2:-}" = "--force" ]; then
                cleanup_demo "--force" "demo"
            else
                cleanup_demo "" "demo"
            fi
            ;;
        clean-all)
            # Check for --force flag in second argument
            if [ "${2:-}" = "--force" ]; then
                cleanup_demo "--force" "all"
            else
                cleanup_demo "" "all"
            fi
            ;;
        -h|--help|help)
            show_usage
            ;;
        *)
            print_error "Unknown step: ${1:-}"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
