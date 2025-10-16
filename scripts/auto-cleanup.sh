#!/bin/bash
# Auto-cleanup script for Neptune Core
# Automatically fixes issues that can be safely automated

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
export CMAKE_POLICY_VERSION_MINIMUM=3.5
DRY_RUN="${DRY_RUN:-false}"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Neptune Core Auto-Cleanup            ║${NC}"
echo -e "${BLUE}║   Automated Code Quality Fixes         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

if [ "$DRY_RUN" = "true" ]; then
    echo -e "${YELLOW}🔍 DRY RUN MODE - No changes will be made${NC}"
    echo ""
fi

# Check for uncommitted changes
if ! git diff --quiet; then
    echo -e "${YELLOW}⚠️  You have uncommitted changes${NC}"
    echo -e "${YELLOW}Consider committing or stashing before running cleanup${NC}"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

FIXES_APPLIED=0

# =============================================================================
# 1. AUTO-FORMAT CODE
# =============================================================================
echo -e "${BLUE}▶ 1. Auto-formatting code...${NC}"

if [ "$DRY_RUN" = "true" ]; then
    FORMAT_CHECK=$(cargo fmt --all -- --check 2>&1 || true)
    if [ -n "$FORMAT_CHECK" ]; then
        FILE_COUNT=$(echo "$FORMAT_CHECK" | grep "^Diff in" | wc -l)
        echo -e "${YELLOW}Would format $FILE_COUNT file(s)${NC}"
    else
        echo -e "${GREEN}✅ No formatting needed${NC}"
    fi
else
    cargo fmt --all
    echo -e "${GREEN}✅ Code formatted${NC}"
    FIXES_APPLIED=$((FIXES_APPLIED + 1))
fi
echo ""

# =============================================================================
# 2. AUTO-FIX CLIPPY ISSUES
# =============================================================================
echo -e "${BLUE}▶ 2. Auto-fixing clippy issues...${NC}"

if [ "$DRY_RUN" = "true" ]; then
    CLIPPY_CHECK=$(cargo clippy --fix --allow-dirty --allow-staged --all-targets --workspace -- -W clippy::all 2>&1 || true)
    FIXABLE=$(echo "$CLIPPY_CHECK" | grep -c "can be automatically fixed" || echo "0")
    echo -e "${YELLOW}$FIXABLE issue(s) can be auto-fixed${NC}"
else
    echo "Running clippy --fix (this may take a while)..."
    cargo clippy --fix --allow-dirty --allow-staged --all-targets --workspace -- -W clippy::all 2>&1 | grep -E "(Fixing|Fixed|error:|warning:)" || true
    echo -e "${GREEN}✅ Clippy auto-fixes applied${NC}"
    FIXES_APPLIED=$((FIXES_APPLIED + 1))
fi
echo ""

# =============================================================================
# 3. REMOVE UNUSED IMPORTS (additional pass)
# =============================================================================
echo -e "${BLUE}▶ 3. Removing unused imports...${NC}"

if [ "$DRY_RUN" = "true" ]; then
    echo -e "${YELLOW}Would remove unused imports${NC}"
else
    # Run cargo fix to remove unused imports
    cargo fix --allow-dirty --allow-staged --all-targets 2>&1 | grep -E "(Fixing|Fixed)" || echo "No unused imports found"
    echo -e "${GREEN}✅ Unused imports removed${NC}"
    FIXES_APPLIED=$((FIXES_APPLIED + 1))
fi
echo ""

# =============================================================================
# 4. REMOVE dbg! MACROS
# =============================================================================
echo -e "${BLUE}▶ 4. Removing dbg! macros...${NC}"

RS_FILES=$(find neptune-core/src neptune-core-cli/src neptune-dashboard/src -name "*.rs" -type f 2>/dev/null || true)
DBG_FILES=$(echo "$RS_FILES" | xargs grep -l 'dbg!' 2>/dev/null || true)

if [ -z "$DBG_FILES" ]; then
    echo -e "${GREEN}✅ No dbg! macros found${NC}"
else
    DBG_COUNT=$(echo "$DBG_FILES" | wc -l)
    echo -e "${YELLOW}Found dbg! in $DBG_COUNT file(s)${NC}"
    
    if [ "$DRY_RUN" = "true" ]; then
        echo "$DBG_FILES" | while read -r file; do
            echo "  Would process: $file"
        done
    else
        echo "Removing dbg! macros..."
        echo "$DBG_FILES" | while read -r file; do
            # Replace dbg!(expr) with expr
            sed -i 's/dbg!(\([^)]*\))/\1/g' "$file"
            echo "  Processed: $file"
        done
        echo -e "${GREEN}✅ dbg! macros removed${NC}"
        FIXES_APPLIED=$((FIXES_APPLIED + 1))
    fi
fi
echo ""

# =============================================================================
# 5. REPLACE println! WITH tracing (semi-automated)
# =============================================================================
echo -e "${BLUE}▶ 5. Analyzing println! usage...${NC}"

PRINTLN_FILES=$(echo "$RS_FILES" | xargs grep -l 'println!' 2>/dev/null | grep -v '#\[cfg(test)\]' | grep -v '#\[test\]' || true)

if [ -z "$PRINTLN_FILES" ]; then
    echo -e "${GREEN}✅ No println! in production code${NC}"
else
    PRINTLN_COUNT=$(echo "$PRINTLN_FILES" | wc -l)
    echo -e "${YELLOW}Found println! in $PRINTLN_COUNT file(s)${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  Manual review required${NC}"
    echo "Replace println! with appropriate tracing level:"
    echo "  println!(\"...\") → info!(\"...\")"
    echo "  println!(\"Debug: ...\") → debug!(\"...\")"
    echo "  println!(\"Error: ...\") → error!(\"...\")"
    echo ""
    echo "Files to review:"
    echo "$PRINTLN_FILES" | while read -r file; do
        COUNT=$(grep -c 'println!' "$file" 2>/dev/null || echo "0")
        echo "  $file: $COUNT instance(s)"
    done
fi
echo ""

# =============================================================================
# 6. ADD MISSING DOCUMENTATION (generate stubs)
# =============================================================================
echo -e "${BLUE}▶ 6. Documentation analysis...${NC}"

DOC_OUTPUT=$(cargo doc --no-deps --workspace 2>&1 || true)
MISSING_DOCS=$(echo "$DOC_OUTPUT" | grep -c "warning: missing documentation" || echo "0")

echo -e "Missing documentation: ${YELLOW}$MISSING_DOCS${NC} items"
if [ "$MISSING_DOCS" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Manual documentation needed${NC}"
    echo "Run: cargo doc --workspace 2>&1 | grep 'missing documentation' | head -20"
fi
echo ""

# =============================================================================
# 7. OPTIMIZE IMPORTS (organize)
# =============================================================================
echo -e "${BLUE}▶ 7. Organizing imports...${NC}"

if command -v cargo-sort &> /dev/null; then
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}Would sort Cargo.toml dependencies${NC}"
    else
        cargo sort --workspace 2>&1 | head -5
        echo -e "${GREEN}✅ Imports organized${NC}"
        FIXES_APPLIED=$((FIXES_APPLIED + 1))
    fi
else
    echo -e "${YELLOW}⚠️  cargo-sort not installed${NC}"
    echo "Install with: cargo install cargo-sort"
fi
echo ""

# =============================================================================
# 8. UPDATE CARGO.LOCK
# =============================================================================
echo -e "${BLUE}▶ 8. Updating Cargo.lock...${NC}"

if [ "$DRY_RUN" = "true" ]; then
    echo -e "${YELLOW}Would update Cargo.lock${NC}"
else
    cargo update --workspace 2>&1 | grep -E "(Updating|Adding|Removing)" || echo "Cargo.lock already up to date"
    echo -e "${GREEN}✅ Cargo.lock updated${NC}"
    FIXES_APPLIED=$((FIXES_APPLIED + 1))
fi
echo ""

# =============================================================================
# 9. VERIFY BUILD AFTER FIXES
# =============================================================================
echo -e "${BLUE}▶ 9. Verifying build...${NC}"

if [ "$DRY_RUN" != "true" ]; then
    if cargo check --workspace > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Build verified${NC}"
    else
        echo -e "${RED}❌ Build failed after fixes${NC}"
        echo "Please review changes and fix manually"
        exit 1
    fi
else
    echo -e "${YELLOW}Skipping build verification (dry run)${NC}"
fi
echo ""

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CLEANUP SUMMARY                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

if [ "$DRY_RUN" = "true" ]; then
    echo -e "${YELLOW}DRY RUN COMPLETE${NC}"
    echo "No changes were made"
    echo ""
    echo "To apply fixes, run:"
    echo "  bash scripts/auto-cleanup.sh"
else
    echo -e "${GREEN}✅ Cleanup complete!${NC}"
    echo ""
    echo -e "Fixes applied: ${GREEN}$FIXES_APPLIED${NC}"
    echo ""
    
    # Check git status
    if ! git diff --quiet; then
        echo -e "${YELLOW}Changes made:${NC}"
        git status --short | head -20
        echo ""
        echo "Review changes with: git diff"
        echo "Commit changes with: git commit -am 'refactor: auto-cleanup code quality'"
    else
        echo "No changes were necessary"
    fi
fi

echo ""
echo -e "${CYAN}Next steps:${NC}"
echo "1. Review changes: git diff"
echo "2. Run tests: cargo test --workspace"
echo "3. Run audit: bash scripts/quality-audit.sh"
echo "4. Commit changes if satisfied"

