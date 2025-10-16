#!/bin/bash
# Install Git hooks for Neptune Core
#
# This script configures Git to use custom hooks from .githooks/

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}🔧 Installing Git Hooks${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo -e "${RED}❌ Not in a git repository root${NC}"
    echo "Please run this script from the Neptune Core root directory"
    exit 1
fi

# Configure Git to use .githooks directory
echo -e "${BLUE}▶ Configuring Git hooks path...${NC}"
git config core.hooksPath .githooks

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Git hooks path configured${NC}"
else
    echo -e "${RED}❌ Failed to configure hooks path${NC}"
    exit 1
fi

# Make hooks executable
echo -e "${BLUE}▶ Making hooks executable...${NC}"

HOOKS=("pre-commit" "pre-push" "commit-msg")
for hook in "${HOOKS[@]}"; do
    if [ -f ".githooks/$hook" ]; then
        chmod +x ".githooks/$hook"
        echo -e "${GREEN}  ✅ $hook${NC}"
    else
        echo -e "${YELLOW}  ⚠️  $hook not found${NC}"
    fi
done

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}✅ Git Hooks Installed!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

echo -e "${BLUE}Installed hooks:${NC}"
echo ""
echo -e "  ${GREEN}pre-commit${NC}  - Runs before each commit"
echo "    • Format check (cargo fmt)"
echo "    • Clippy lints"
echo "    • Build check"
echo "    • Quick tests"
echo "    • P2P module validation"
echo "    • Security audit"
echo "    • Code pattern checks"
echo ""
echo -e "  ${GREEN}pre-push${NC}    - Runs before pushing to remote"
echo "    • Full release build"
echo "    • Comprehensive test suite"
echo "    • Documentation build"
echo "    • P2P module verification"
echo "    • Security audit (strict on master)"
echo "    • Code quality metrics"
echo "    • Branch-specific checks"
echo ""
echo -e "  ${GREEN}commit-msg${NC}  - Validates commit message format"
echo "    • Conventional Commits format"
echo "    • Message length validation"
echo "    • Imperative mood check"
echo ""

echo -e "${YELLOW}Tips:${NC}"
echo ""
echo -e "  ${BLUE}Skip hooks temporarily:${NC}"
echo "    SKIP_HOOKS=true git commit"
echo "    SKIP_HOOKS=true git push"
echo "    git commit --no-verify"
echo ""
echo -e "  ${BLUE}Check hook status:${NC}"
echo "    git config core.hooksPath"
echo ""
echo -e "  ${BLUE}Uninstall hooks:${NC}"
echo "    git config --unset core.hooksPath"
echo ""

echo -e "${GREEN}Happy coding! 🚀${NC}"

