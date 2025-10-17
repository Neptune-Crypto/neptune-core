#!/bin/bash
# Quality Audit Script for Neptune Core
# Tests what the pre-commit/pre-push hooks would catch and provides cleanup guidance

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
export CMAKE_POLICY_VERSION_MINIMUM=3.5
REPORT_FILE="quality-audit-report.md"

# Print header
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Neptune Core Quality Audit          ║${NC}"
echo -e "${BLUE}║   Comprehensive Codebase Analysis     ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo ""

# Start report
cat > "$REPORT_FILE" << 'EOF'
# Neptune Core Quality Audit Report

**Generated:** $(date)
**Branch:** $(git rev-parse --abbrev-ref HEAD)
**Commit:** $(git rev-parse --short HEAD)

---

EOF

echo "📝 Report will be saved to: $REPORT_FILE"
echo ""

# =============================================================================
# 1. FORMAT ISSUES
# =============================================================================
echo -e "${MAGENTA}▶ 1. FORMAT ISSUES${NC}"
echo ""

FORMAT_OUTPUT=$(cargo fmt --all -- --check 2>&1 || true)
if [ -z "$FORMAT_OUTPUT" ]; then
    echo -e "${GREEN}✅ No formatting issues found${NC}"
    echo "## 1. Format Issues" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "✅ **Status:** All files properly formatted" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
else
    FILE_COUNT=$(echo "$FORMAT_OUTPUT" | grep "^Diff in" | wc -l)
    echo -e "${RED}❌ Found formatting issues in $FILE_COUNT file(s)${NC}"
    echo ""
    echo "Files needing formatting:"
    echo "$FORMAT_OUTPUT" | grep "^Diff in" | sed 's/^Diff in /  • /'
    echo ""
    echo -e "${CYAN}To fix:${NC} cargo fmt --all"
    echo ""

    echo "## 1. Format Issues" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "❌ **Status:** $FILE_COUNT file(s) need formatting" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**Files:**" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$FORMAT_OUTPUT" | grep "^Diff in" | sed 's/^Diff in //' >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**Fix:** \`cargo fmt --all\`" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# =============================================================================
# 2. CLIPPY WARNINGS AND ERRORS
# =============================================================================
echo -e "${MAGENTA}▶ 2. CLIPPY ANALYSIS${NC}"
echo ""

CLIPPY_OUTPUT=$(cargo clippy --all-targets --workspace -- -W clippy::all -W clippy::pedantic 2>&1 || true)

CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "^error:" || echo "0")
CLIPPY_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -c "^warning:" || echo "0")

echo -e "Clippy errors:   ${RED}$CLIPPY_ERRORS${NC}"
echo -e "Clippy warnings: ${YELLOW}$CLIPPY_WARNINGS${NC}"
echo ""

echo "## 2. Clippy Analysis" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Errors:** $CLIPPY_ERRORS" >> "$REPORT_FILE"
echo "**Warnings:** $CLIPPY_WARNINGS" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

if [ "$CLIPPY_ERRORS" -gt 0 ]; then
    echo -e "${RED}Top 10 errors:${NC}"
    echo "$CLIPPY_OUTPUT" | grep -A 3 "^error:" | head -40
    echo ""

    echo "### Top Errors" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$CLIPPY_OUTPUT" | grep -A 3 "^error:" | head -40 >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

if [ "$CLIPPY_WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}Top 10 warnings:${NC}"
    echo "$CLIPPY_OUTPUT" | grep -A 3 "^warning:" | head -40
    echo ""

    echo "### Top Warnings" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$CLIPPY_OUTPUT" | grep -A 3 "^warning:" | head -40 >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# Categorize warnings
echo "### Warning Categories" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "$CLIPPY_OUTPUT" | grep "^warning:" | sed 's/.*\[\(.*\)\]/\1/' | sort | uniq -c | sort -rn | head -20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# =============================================================================
# 3. CODE PATTERN ISSUES
# =============================================================================
echo -e "${MAGENTA}▶ 3. CODE PATTERN ANALYSIS${NC}"
echo ""

echo "## 3. Code Pattern Issues" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# TODO/FIXME/HACK
echo -e "${YELLOW}Searching for TODO/FIXME/HACK...${NC}"
TODO_FILES=$(find neptune-core/src neptune-core-cli/src neptune-dashboard/src -name "*.rs" -type f 2>/dev/null || true)
TODO_COUNT=$(echo "$TODO_FILES" | xargs grep -n -E '\b(TODO|FIXME|HACK|XXX)\b' 2>/dev/null | wc -l || echo "0")
echo -e "Total markers: ${YELLOW}$TODO_COUNT${NC}"

if [ "$TODO_COUNT" -gt 0 ]; then
    echo ""
    echo "Top 20 instances:"
    echo "$TODO_FILES" | xargs grep -n -E '\b(TODO|FIXME|HACK|XXX)\b' 2>/dev/null | head -20 | while IFS=: read -r file line content; do
        echo "  $file:$line"
        echo "    $(echo "$content" | xargs)"
    done
    echo ""
fi

echo "### TODO/FIXME/HACK Markers" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Total:** $TODO_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
if [ "$TODO_COUNT" -gt 0 ]; then
    echo "**Top 20:**" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$TODO_FILES" | xargs grep -n -E '\b(TODO|FIXME|HACK|XXX)\b' 2>/dev/null | head -20 >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# println! in non-test code
echo -e "${YELLOW}Searching for println! in production code...${NC}"
PRINTLN_COUNT=$(echo "$TODO_FILES" | xargs grep -n 'println!' 2>/dev/null | grep -v '#\[cfg(test)\]' | grep -v '#\[test\]' | wc -l || echo "0")
echo -e "Found: ${YELLOW}$PRINTLN_COUNT${NC}"

if [ "$PRINTLN_COUNT" -gt 0 ]; then
    echo ""
    echo "Instances:"
    echo "$TODO_FILES" | xargs grep -n 'println!' 2>/dev/null | grep -v '#\[cfg(test)\]' | grep -v '#\[test\]' | head -10
    echo ""
fi

echo "### println! in Production Code" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Total:** $PRINTLN_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
if [ "$PRINTLN_COUNT" -gt 0 ]; then
    echo "**Instances:**" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$TODO_FILES" | xargs grep -n 'println!' 2>/dev/null | grep -v '#\[cfg(test)\]' | grep -v '#\[test\]' | head -10 >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# unwrap() usage
echo -e "${YELLOW}Analyzing unwrap() usage...${NC}"
UNWRAP_COUNT=$(echo "$TODO_FILES" | xargs grep -c '\.unwrap()' 2>/dev/null | awk -F: '{s+=$2}END{print s}' || echo "0")
echo -e "Total unwrap() calls: ${YELLOW}$UNWRAP_COUNT${NC}"

TOP_UNWRAP_FILES=$(echo "$TODO_FILES" | xargs grep -c '\.unwrap()' 2>/dev/null | sort -t: -k2 -rn | head -10)
if [ -n "$TOP_UNWRAP_FILES" ]; then
    echo ""
    echo "Files with most unwrap() calls:"
    echo "$TOP_UNWRAP_FILES" | while IFS=: read -r file count; do
        if [ "$count" -gt 0 ]; then
            echo "  $file: $count"
        fi
    done
    echo ""
fi

echo "### unwrap() Usage" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Total:** $UNWRAP_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Top Files:**" >> "$REPORT_FILE"
echo "\`\`\`" >> "$REPORT_FILE"
echo "$TOP_UNWRAP_FILES" >> "$REPORT_FILE"
echo "\`\`\`" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# dbg! macro
echo -e "${YELLOW}Searching for dbg! macro...${NC}"
DBG_COUNT=$(echo "$TODO_FILES" | xargs grep -n 'dbg!' 2>/dev/null | wc -l || echo "0")
echo -e "Found: ${YELLOW}$DBG_COUNT${NC}"

if [ "$DBG_COUNT" -gt 0 ]; then
    echo ""
    echo "Instances:"
    echo "$TODO_FILES" | xargs grep -n 'dbg!' 2>/dev/null
    echo ""
fi

echo "### dbg! Macro Usage" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Total:** $DBG_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
if [ "$DBG_COUNT" -gt 0 ]; then
    echo "**Instances:**" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$TODO_FILES" | xargs grep -n 'dbg!' 2>/dev/null >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# =============================================================================
# 4. FILE SIZE ANALYSIS
# =============================================================================
echo -e "${MAGENTA}▶ 4. FILE SIZE ANALYSIS${NC}"
echo ""

LARGE_FILES=$(find neptune-core/src neptune-core-cli/src neptune-dashboard/src -name "*.rs" -type f 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        LINES=$(wc -l < "$file")
        if [ "$LINES" -gt 1000 ]; then
            echo "$file:$LINES"
        fi
    fi
done | sort -t: -k2 -rn)

LARGE_FILE_COUNT=$(echo "$LARGE_FILES" | grep -c ":" || echo "0")

echo -e "Files >1000 lines: ${YELLOW}$LARGE_FILE_COUNT${NC}"

if [ "$LARGE_FILE_COUNT" -gt 0 ]; then
    echo ""
    echo "Large files:"
    echo "$LARGE_FILES" | while IFS=: read -r file lines; do
        echo "  $file: $lines lines"
    done
    echo ""
fi

echo "## 4. File Size Analysis" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Files >1000 lines:** $LARGE_FILE_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
if [ "$LARGE_FILE_COUNT" -gt 0 ]; then
    echo "**Large Files:**" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "$LARGE_FILES" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# =============================================================================
# 5. BUILD WARNINGS
# =============================================================================
echo -e "${MAGENTA}▶ 5. BUILD WARNINGS${NC}"
echo ""

echo "Building workspace to count warnings..."
BUILD_OUTPUT=$(cargo build --workspace 2>&1 || true)
WARNING_COUNT=$(echo "$BUILD_OUTPUT" | grep -c "^warning:" || echo "0")

echo -e "Total warnings: ${YELLOW}$WARNING_COUNT${NC}"
echo -e "Goal: ${GREEN}<50${NC}"
echo ""

if [ "$WARNING_COUNT" -gt 0 ]; then
    echo "Warning breakdown:"
    echo "$BUILD_OUTPUT" | grep "^warning:" | sed 's/.*warning: //' | cut -d'[' -f1 | sort | uniq -c | sort -rn | head -15
    echo ""
fi

echo "## 5. Build Warnings" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Total:** $WARNING_COUNT" >> "$REPORT_FILE"
echo "**Goal:** <50" >> "$REPORT_FILE"
echo "**Progress:** $(echo "scale=1; 100 * (144 - $WARNING_COUNT) / 144" | bc)% reduction from initial 144" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "### Warning Types (Top 15)" >> "$REPORT_FILE"
echo "\`\`\`" >> "$REPORT_FILE"
echo "$BUILD_OUTPUT" | grep "^warning:" | sed 's/.*warning: //' | cut -d'[' -f1 | sort | uniq -c | sort -rn | head -15 >> "$REPORT_FILE"
echo "\`\`\`" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# =============================================================================
# 6. SECURITY AUDIT
# =============================================================================
echo -e "${MAGENTA}▶ 6. SECURITY AUDIT${NC}"
echo ""

if command -v cargo-audit &> /dev/null; then
    AUDIT_OUTPUT=$(cargo audit 2>&1 || true)

    VULNERABILITIES=$(echo "$AUDIT_OUTPUT" | grep -c "vulnerability" || echo "0")
    echo -e "Vulnerabilities: ${YELLOW}$VULNERABILITIES${NC}"

    if [ "$VULNERABILITIES" -gt 0 ]; then
        echo ""
        echo "Details:"
        echo "$AUDIT_OUTPUT" | grep -A 10 "vulnerability"
        echo ""
    fi

    echo "## 6. Security Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**Vulnerabilities:** $VULNERABILITIES" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    if [ "$VULNERABILITIES" -gt 0 ]; then
        echo "**Details:**" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "$AUDIT_OUTPUT" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
else
    echo -e "${YELLOW}⚠️  cargo-audit not installed${NC}"
    echo -e "Install with: ${CYAN}cargo install cargo-audit${NC}"
    echo ""

    echo "## 6. Security Audit" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "⚠️ **cargo-audit not installed**" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# =============================================================================
# 7. P2P MODULE VERIFICATION
# =============================================================================
echo -e "${MAGENTA}▶ 7. P2P MODULE VERIFICATION${NC}"
echo ""

CRITICAL_P2P_FILES=(
    "neptune-core/src/p2p/state/reputation.rs"
    "neptune-core/src/p2p/state/connection_tracker.rs"
    "neptune-core/src/p2p/connection/validator.rs"
    "neptune-core/src/p2p/connection/acceptor.rs"
    "neptune-core/src/p2p/connection/initiator.rs"
    "neptune-core/src/p2p/protocol/handler.rs"
)

P2P_MISSING=0
for file in "${CRITICAL_P2P_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Missing: $file${NC}"
        P2P_MISSING=$((P2P_MISSING + 1))
    else
        echo -e "${GREEN}✅ Present: $(basename $file)${NC}"
    fi
done

echo ""
if [ $P2P_MISSING -eq 0 ]; then
    echo -e "${GREEN}✅ All P2P components present${NC}"
else
    echo -e "${RED}❌ $P2P_MISSING P2P components missing${NC}"
fi
echo ""

echo "## 7. P2P Module Verification" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Status:** $([ $P2P_MISSING -eq 0 ] && echo "✅ All components present" || echo "❌ $P2P_MISSING components missing")" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# =============================================================================
# 8. TEST STATUS
# =============================================================================
echo -e "${MAGENTA}▶ 8. TEST STATUS (Quick Check)${NC}"
echo ""

echo "Running quick test check..."
TEST_OUTPUT=$(cargo test --lib --no-fail-fast 2>&1 || true)

if echo "$TEST_OUTPUT" | grep -q "test result: FAILED"; then
    FAILED=$(echo "$TEST_OUTPUT" | grep "test result:" | tail -1 | grep -oP '\d+(?= failed)' || echo "0")
    PASSED=$(echo "$TEST_OUTPUT" | grep "test result:" | tail -1 | grep -oP '\d+(?= passed)' || echo "0")
    echo -e "${RED}❌ Tests failed${NC}"
    echo -e "Passed: ${GREEN}$PASSED${NC}"
    echo -e "Failed: ${RED}$FAILED${NC}"

    echo "## 8. Test Status" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "❌ **Status:** Tests failed" >> "$REPORT_FILE"
    echo "**Passed:** $PASSED" >> "$REPORT_FILE"
    echo "**Failed:** $FAILED" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
else
    PASSED=$(echo "$TEST_OUTPUT" | grep "test result:" | tail -1 | grep -oP '\d+(?= passed)' || echo "0")
    echo -e "${GREEN}✅ All tests passed ($PASSED)${NC}"

    echo "## 8. Test Status" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "✅ **Status:** All tests passed" >> "$REPORT_FILE"
    echo "**Total:** $PASSED" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi
echo ""

# =============================================================================
# 9. DOCUMENTATION COVERAGE
# =============================================================================
echo -e "${MAGENTA}▶ 9. DOCUMENTATION COVERAGE${NC}"
echo ""

echo "Checking documentation..."
DOC_OUTPUT=$(cargo doc --no-deps --workspace 2>&1 || true)
DOC_WARNINGS=$(echo "$DOC_OUTPUT" | grep -c "warning: missing documentation" || echo "0")

echo -e "Missing documentation warnings: ${YELLOW}$DOC_WARNINGS${NC}"
echo ""

echo "## 9. Documentation Coverage" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Missing Documentation:** $DOC_WARNINGS items" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AUDIT SUMMARY                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

cat >> "$REPORT_FILE" << EOF

---

## Summary & Action Plan

EOF

# Calculate score
TOTAL_ISSUES=$((CLIPPY_ERRORS + TODO_COUNT + DBG_COUNT + P2P_MISSING))
WARNINGS_TOTAL=$((CLIPPY_WARNINGS + PRINTLN_COUNT + LARGE_FILE_COUNT))

echo -e "${RED}Critical Issues:${NC} $TOTAL_ISSUES"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS_TOTAL"
echo -e "${BLUE}Build Warnings:${NC} $WARNING_COUNT / 50 goal"
echo ""

echo "### Critical Issues: $TOTAL_ISSUES" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- Clippy errors: $CLIPPY_ERRORS" >> "$REPORT_FILE"
echo "- TODO/FIXME markers: $TODO_COUNT" >> "$REPORT_FILE"
echo "- dbg! macros: $DBG_COUNT" >> "$REPORT_FILE"
echo "- Missing P2P components: $P2P_MISSING" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "### Warnings: $WARNINGS_TOTAL" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- Clippy warnings: $CLIPPY_WARNINGS" >> "$REPORT_FILE"
echo "- println! in production: $PRINTLN_COUNT" >> "$REPORT_FILE"
echo "- Large files (>1000 lines): $LARGE_FILE_COUNT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo -e "${CYAN}Priority Actions:${NC}"
echo ""

if [ "$CLIPPY_ERRORS" -gt 0 ]; then
    echo "1. ${RED}FIX CLIPPY ERRORS${NC} (blocks commit)"
    echo "   cargo clippy --fix --allow-dirty --allow-staged"
    echo ""
fi

if [ -n "$FORMAT_OUTPUT" ]; then
    echo "2. ${RED}FIX FORMATTING${NC} (blocks commit)"
    echo "   cargo fmt --all"
    echo ""
fi

if [ "$DBG_COUNT" -gt 0 ]; then
    echo "3. ${YELLOW}REMOVE dbg! MACROS${NC}"
    echo "   Search and remove manually"
    echo ""
fi

if [ "$WARNING_COUNT" -gt 50 ]; then
    echo "4. ${YELLOW}REDUCE BUILD WARNINGS${NC} (current: $WARNING_COUNT, goal: <50)"
    echo "   cargo clippy --fix --allow-dirty"
    echo ""
fi

if [ "$TODO_COUNT" -gt 50 ]; then
    echo "5. ${YELLOW}ADDRESS TODOs${NC} (current: $TODO_COUNT)"
    echo "   Review and resolve or remove"
    echo ""
fi

echo "---"
echo ""
echo -e "${GREEN}✅ Audit complete!${NC}"
echo -e "${BLUE}📝 Full report saved to: $REPORT_FILE${NC}"
echo ""
echo -e "${CYAN}View report:${NC} cat $REPORT_FILE"
echo -e "${CYAN}Or open in editor:${NC} \$EDITOR $REPORT_FILE"

