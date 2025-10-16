# Git Hooks for Neptune Core

This directory contains custom Git hooks to ensure code quality and consistency before commits reach CI/CD.

## 🎯 Purpose

The hooks provide:

- **Fast local feedback** (catch issues before CI/CD)
- **Consistent code quality** (enforced formatting, linting)
- **Security validation** (vulnerability scanning)
- **P2P module protection** (validates critical components)
- **Commit message standards** (Conventional Commits)

## 📦 Installation

### Quick Install

```bash
# From the Neptune Core root directory
bash .githooks/install-hooks.sh
```

### Manual Install

```bash
# Configure Git to use .githooks directory
git config core.hooksPath .githooks

# Make hooks executable
chmod +x .githooks/pre-commit
chmod +x .githooks/pre-push
chmod +x .githooks/commit-msg
```

### Verify Installation

```bash
git config core.hooksPath
# Should output: .githooks
```

## 🪝 Available Hooks

### 1. `pre-commit` ⚡ (Fast Checks)

Runs before **every commit** to catch basic issues.

**Checks:**

1. ✅ **Format Check** (`cargo fmt`)

   - Enforces consistent code formatting
   - Blocks commit if formatting issues found

2. ✅ **Clippy Lints** (`cargo clippy`)

   - Runs static analysis
   - Blocks on errors, warns on warnings

3. ✅ **Build Check** (`cargo check`)

   - Ensures code compiles
   - Blocks commit if build fails

4. ✅ **Quick Tests**

   - Runs unit tests for affected crates only
   - Fast feedback (seconds, not minutes)

5. ✅ **P2P Module Check** (if P2P files changed)

   - Validates P2P module structure
   - Runs P2P-specific tests
   - **Unique to our fork!**

6. ✅ **Security Audit** (if cargo-audit installed)

   - Scans for known vulnerabilities
   - Warns but doesn't block

7. ✅ **Code Pattern Checks**

   - Detects TODO/FIXME/HACK comments
   - Warns about `println!` in non-test code
   - Warns about excessive `unwrap()` calls
   - Detects `dbg!` macros

8. ✅ **File Size Check**

   - Warns about files > 1000 lines

9. ✅ **Commit Message Validation**
   - Checks Conventional Commits format
   - Validates message length

**Execution Time:** ~10-30 seconds (with cache)

**Can be skipped:** Yes (use `SKIP_HOOKS=true` or `--no-verify`)

---

### 2. `pre-push` 🚀 (Comprehensive Checks)

Runs before **pushing to remote** to ensure production-ready code.

**Checks:**

1. ✅ **Branch Protection**

   - Warns when pushing to master/main
   - Prompts for confirmation

2. ✅ **Full Release Build**

   - Builds all packages in release mode
   - Ensures production binaries compile

3. ✅ **Comprehensive Test Suite**

   - Runs all tests (lib, bins, integration)
   - Blocks push if any tests fail

4. ✅ **Documentation Build**

   - Ensures docs build without errors
   - Validates doc comments

5. ✅ **P2P Module Verification**

   - Checks all critical P2P components exist
   - Runs full P2P test suite
   - **Critical for our hardened fork!**

6. ✅ **Security Audit** (strict on master)

   - Blocks push to master if high/critical vulnerabilities
   - Warns on other branches

7. ✅ **Code Quality Metrics**

   - Tracks warning count (goal: <50)
   - Counts TODO/FIXME comments

8. ✅ **Comprehensive Clippy**

   - Runs clippy in pedantic mode
   - Provides detailed feedback

9. ✅ **Commit History Check**

   - Shows unpushed commits
   - Helps review before push

10. ✅ **Branch-Specific Checks**
    - **master/main**: Strict (zero errors)
    - **develop**: Standard checks
    - **feature/\***: Standard checks

**Execution Time:** ~2-5 minutes (with cache)

**Can be skipped:** Yes, but **NOT recommended** for master

---

### 3. `commit-msg` 📝 (Message Validation)

Validates commit message format using **Conventional Commits** standard.

**Checks:**

1. ✅ **Conventional Commits Format**

   ```
   <type>(<scope>): <description>

   [optional body]

   [optional footer]
   ```

2. ✅ **Valid Types**

   - `feat`: New feature
   - `fix`: Bug fix
   - `docs`: Documentation changes
   - `style`: Code formatting (no logic change)
   - `refactor`: Code refactoring
   - `perf`: Performance improvements
   - `test`: Test changes
   - `chore`: Maintenance
   - `ci`: CI/CD changes
   - `build`: Build system changes
   - `revert`: Revert previous commit

3. ✅ **Message Length**

   - Minimum: 10 characters
   - Recommended: ≤ 72 characters (first line)

4. ✅ **Imperative Mood**

   - "Add feature" ✅
   - "Added feature" ❌

5. ✅ **No Trailing Period**
   - "Add feature" ✅
   - "Add feature." ❌

**Examples:**

```bash
# Good commits ✅
git commit -m "feat(p2p): Add connection rate limiting"
git commit -m "fix(cli): Resolve wallet initialization bug"
git commit -m "docs: Update installation instructions"
git commit -m "refactor(state): Simplify peer management"

# Bad commits ❌
git commit -m "updates"  # Too short, no type
git commit -m "feat: added new feature."  # Past tense, trailing period
git commit -m "fix wallet"  # No colon after type
```

**Execution Time:** <1 second

**Can be skipped:** Yes, but **strongly discouraged**

---

## 🔧 Configuration

### Environment Variables

```bash
# Skip all hooks (not recommended)
SKIP_HOOKS=true git commit
SKIP_HOOKS=true git push

# Skip specific hook
git commit --no-verify
git push --no-verify
```

### Hook Execution

```bash
# Test pre-commit hook manually
.githooks/pre-commit

# Test pre-push hook manually
.githooks/pre-push

# Test commit-msg hook manually
echo "test: Add feature" > /tmp/test-msg
.githooks/commit-msg /tmp/test-msg
```

## 📊 Hook Flow Diagram

```
Commit Attempt
    ↓
┌─────────────────────┐
│   commit-msg        │ ← Validate message format
└─────────────────────┘
    ↓
┌─────────────────────┐
│   pre-commit        │ ← Fast quality checks
│   • Format          │
│   • Clippy          │
│   • Build           │
│   • Quick tests     │
│   • P2P check       │
└─────────────────────┘
    ↓
Commit Created
    ↓
Push Attempt
    ↓
┌─────────────────────┐
│   pre-push          │ ← Comprehensive checks
│   • Full build      │
│   • All tests       │
│   • Documentation   │
│   • P2P verify      │
│   • Security audit  │
└─────────────────────┘
    ↓
Push Successful
```

## 🎯 When Hooks Run

| Hook         | Trigger      | Blocks | Time   | Can Skip |
| ------------ | ------------ | ------ | ------ | -------- |
| `commit-msg` | Every commit | Yes    | <1s    | Yes      |
| `pre-commit` | Every commit | Yes    | 10-30s | Yes      |
| `pre-push`   | Before push  | Yes    | 2-5m   | Yes      |

## 💡 Tips & Best Practices

### For Developers

1. **Install hooks immediately** after cloning

   ```bash
   bash .githooks/install-hooks.sh
   ```

2. **Run checks manually** before committing

   ```bash
   cargo fmt --all
   cargo clippy --workspace
   cargo test --workspace
   ```

3. **Use meaningful commit messages**

   - Follow Conventional Commits
   - Be specific about changes
   - Reference issues when applicable

4. **Address warnings proactively**

   - Don't accumulate TODOs/FIXMEs
   - Fix clippy warnings
   - Keep files under 1000 lines

5. **Test locally before pushing**
   - Hooks catch most issues
   - But local testing is faster
   - Use `cargo watch` for live feedback

### For Feature Development

```bash
# Start feature
git checkout -b feature/my-feature develop

# Make changes
# ... edit files ...

# Commit (pre-commit runs)
git commit -m "feat(p2p): Add new connection validator"
# ✅ Format check
# ✅ Clippy
# ✅ Build
# ✅ Tests

# Push (pre-push runs)
git push origin feature/my-feature
# ✅ Full build
# ✅ All tests
# ✅ Documentation
# ✅ P2P verification
```

### For Hotfixes

```bash
# Quick hotfix
git checkout -b hotfix/critical-bug master

# Fix the issue
# ... make minimal changes ...

# Commit and push
git commit -m "fix(core): Resolve critical memory leak"
git push origin hotfix/critical-bug

# Hooks ensure quality even for urgent fixes
```

## 🚨 Troubleshooting

### Hook Not Running

```bash
# Check hooks path
git config core.hooksPath
# Should be: .githooks

# Reinstall hooks
bash .githooks/install-hooks.sh

# Check hook is executable
ls -la .githooks/
# Should show 'x' permission
```

### Hook Failing Unexpectedly

```bash
# Run hook manually to see full output
.githooks/pre-commit

# Check Rust toolchain
rustc --version
cargo --version

# Update toolchain
rustup update stable

# Install missing components
rustup component add rustfmt clippy
```

### Slow Hook Execution

```bash
# Check cargo cache
du -sh ~/.cargo

# Clean build artifacts
cargo clean

# Update dependencies
cargo update

# Use cargo-watch for live feedback
cargo install cargo-watch
cargo watch -x check -x test
```

### False Positives

```bash
# Skip specific check (temporary)
SKIP_HOOKS=true git commit

# Or bypass single hook
git commit --no-verify

# Better: Fix the underlying issue
cargo fmt --all
cargo clippy --fix
```

## 🔄 Updating Hooks

When hooks are updated:

```bash
# Pull latest changes
git pull origin develop

# Hooks are automatically updated
# No need to reinstall unless permissions change

# Verify hooks work
.githooks/pre-commit
```

## 🆚 Comparison: Hooks vs CI/CD

| Aspect          | Git Hooks                 | CI/CD               |
| --------------- | ------------------------- | ------------------- |
| **Speed**       | ⚡ Fast (seconds-minutes) | ⏱️ Slower (minutes) |
| **Feedback**    | 🔄 Immediate              | ⏰ Delayed          |
| **Scope**       | 📦 Local changes          | 🌐 Full codebase    |
| **Environment** | 💻 Developer machine      | ☁️ Cloud runners    |
| **Cost**        | 🆓 Free                   | 💰 Actions minutes  |
| **Bypassable**  | ✅ Yes                    | ❌ No               |
| **Purpose**     | 🚫 Prevent bad commits    | ✅ Verify quality   |

**Best Practice:** Use both!

- Hooks catch issues early (fast feedback)
- CI/CD provides final validation (comprehensive)

## 📈 Benefits

### Before Git Hooks

```
Developer writes code
    ↓
Commits code
    ↓
Pushes to remote
    ↓
CI/CD runs (3-5 minutes)
    ↓
CI/CD fails ❌
    ↓
Developer fixes locally
    ↓
Pushes again
    ↓
Wait for CI/CD again...
```

**Total time:** 10-15 minutes per iteration

### With Git Hooks

```
Developer writes code
    ↓
Commits code
    ↓ (pre-commit runs: 10-30 seconds)
Issue caught ❌
    ↓
Developer fixes immediately
    ↓
Commits again
    ↓ (pre-commit passes ✅)
Pushes to remote
    ↓ (pre-push runs: 2-5 minutes)
All checks pass ✅
    ↓
CI/CD confirms ✅
```

**Total time:** 3-6 minutes (2-3x faster)

### Metrics

- **Time saved:** 50-70% reduction in CI/CD failures
- **Feedback speed:** Seconds vs minutes
- **Cost reduction:** Fewer CI/CD runs
- **Code quality:** Enforced standards before push

## 🔐 Security Considerations

### What Hooks Check

1. **Dependency Vulnerabilities**

   - cargo-audit scans
   - Blocks critical/high on master
   - Warns on other branches

2. **Code Patterns**

   - No `dbg!` macros in production
   - Limited `unwrap()` usage
   - Proper error handling

3. **P2P Module Integrity**
   - Critical components exist
   - DDoS protection intact
   - Tests pass

### What Hooks Don't Check

- Runtime behavior
- Integration with external services
- Performance under load
- Memory leaks (use CI/CD for this)

## 📝 Contributing to Hooks

### Adding New Checks

1. Edit appropriate hook file
2. Test thoroughly
3. Document in this README
4. Update install script if needed

### Hook Development Guidelines

- **Fast execution** (<30s for pre-commit)
- **Clear error messages**
- **Actionable feedback**
- **Graceful degradation** (warn vs block)
- **Respect SKIP_HOOKS** environment variable

## 🔗 Related Documentation

- [CI/CD Pipeline](../docs/ci-cd-pipeline.md)
- [Git Workflow](../docs/git-workflow.md)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

---

**Last Updated:** 2025-10-16
**Maintained By:** Sea of Freedom Fork Team
**Questions?** Open an issue or check the docs!
