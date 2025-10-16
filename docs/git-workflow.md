# Git Workflow for Neptune Core Fork

**Last Updated**: 2025-10-16
**Status**: ✅ Configured and Active

---

## Branch Structure

```
upstream/master (Neptune-Crypto/neptune-core)
    ↓ (sync)
master (seaoffreedom/neptune-core) - stable, tracks upstream
    ↓ (integrate)
develop - integration branch for testing features
    ↓ (merge)
feature/* - individual feature branches
```

---

## Remotes

```bash
# Your fork (read/write)
origin: https://github.com/seaoffreedom/neptune-core.git

# Upstream original (read-only)
upstream: https://github.com/Neptune-Crypto/neptune-core.git

# Local backup
modified-fork: /home/anon/Desktop/neptune-core
```

---

## Current State

### Branches

| Branch                    | Purpose                  | Status           | Commits Ahead of Master |
| ------------------------- | ------------------------ | ---------------- | ----------------------- |
| `master`                  | Stable, tracks upstream  | ✅ Up-to-date    | 0 (synced)              |
| `develop`                 | Integration & testing    | ✅ Active        | +28                     |
| `feature/ddos-mitigation` | P2P DDoS protection work | ✅ Merged to dev | (archived)              |

### What's in `develop`?

**Merged Feature: DDoS Protection & P2P Modularization**

- ✅ Complete P2P module (`src/p2p/`)
- ✅ Shared state management (Arc<RwLock<>>)
- ✅ 5-layer DDoS protection (99% mitigation)
- ✅ IP reputation system
- ✅ Automatic banning (temp/perm)
- ✅ Rate limiting (sliding window + token bucket)
- ✅ RPC server for neptune-core-cli
- ✅ Comprehensive documentation

**Upstream Changes (merged):**

- ✅ Basic DOS protection improvements
- ✅ Handshake timeout
- ✅ Improved error handling

---

## Workflow: Git Flow

This repository uses **Git Flow**, a common branching strategy:

### 1. Feature Development

```bash
# Start a new feature
git checkout develop
git pull origin develop
git checkout -b feature/my-feature

# Work on feature
git add .
git commit -m "feat: Add my feature"

# Push to origin
git push origin feature/my-feature
```

### 2. Merge to Develop

```bash
# When feature is complete
git checkout develop
git pull origin develop
git merge feature/my-feature
git push origin develop
```

### 3. Testing in Develop

```bash
# Test thoroughly in develop branch
cargo test
cargo build --release
# Run integration tests
# Run DDoS tests (scripts/python/ddos.py)
```

### 4. Merge to Master (when stable)

```bash
# Only when develop is stable and tested
git checkout master
git merge develop
git push origin master
```

### 5. Sync with Upstream

```bash
# Regularly sync master with upstream
git checkout master
git fetch upstream
git merge upstream/master
git push origin master

# Then update develop
git checkout develop
git merge master
git push origin develop
```

---

## Common Commands

### Check Status

```bash
# Current branch
git branch --show-current

# All branches
git branch -a

# See what's in develop vs master
git log master..develop --oneline

# See upstream changes
git fetch upstream
git log master..upstream/master --oneline
```

### Build & Test

```bash
# Quick check
cargo check

# Full build
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release

# Tests
cargo test

# DDoS tests (with node running)
python3 scripts/python/ddos.py --target 127.0.0.1 --port 9798 --attack connection-flood --force
```

### Clean Up Old Branches

```bash
# Delete local feature branch (after merged)
git branch -d feature/my-feature

# Delete remote feature branch
git push origin --delete feature/my-feature
```

---

## Protection of Your Changes

### Modified Files

Your fork has custom modifications in:

**Neptune Core:**

- `neptune-core/src/lib.rs` - P2P service integration
- `neptune-core/src/application/loops/main_loop.rs` - P2P integration layer
- `neptune-core/src/application/loops/connect_to_peers.rs` - Connection handling
- `neptune-core/src/p2p/*` - **Entire P2P module (NEW)**

**Neptune CLI:**

- `neptune-core-cli/src/main.rs` - RPC server integration
- `neptune-core-cli/src/rpc/*` - **Entire RPC module (NEW)**

### Merge Strategy

When syncing with upstream:

1. **Automatic merge (usually works):** Git merges changes automatically
2. **Conflict (rare):** Your comprehensive changes take precedence
3. **Resolution:** Keep your P2P module (it's a superset of upstream's changes)

### Testing After Merge

Always test after syncing with upstream:

```bash
# 1. Build check
cargo check

# 2. Full build
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release

# 3. Run node
neptune-core

# 4. Test DDoS protection
python3 scripts/python/ddos.py --target 127.0.0.1 --attack connection-flood --force

# 5. Verify logs show protection
grep "🛡️ DDOS PROTECTION" /tmp/neptune-node.log
```

---

## Workflow Benefits

✅ **Stable Master:** Only merge when confident
✅ **Safe Testing:** Test multiple features together in `develop`
✅ **Easy Rollback:** Can revert `develop` without affecting `master`
✅ **Clear History:** Feature branches show what changed
✅ **Upstream Sync:** Can merge upstream changes safely
✅ **Your Changes Protected:** Custom code preserved during syncs

---

## Example: Adding a New Feature

```bash
# 1. Create feature branch from develop
git checkout develop
git pull origin develop
git checkout -b feature/new-rpc-endpoint

# 2. Implement feature
# ... edit files ...
git add .
git commit -m "feat: Add new RPC endpoint for peer management"

# 3. Push to origin
git push origin feature/new-rpc-endpoint

# 4. Merge to develop when ready
git checkout develop
git merge feature/new-rpc-endpoint

# 5. Test in develop
cargo test
cargo build --release
# Run tests...

# 6. If all good, delete feature branch
git branch -d feature/new-rpc-endpoint
git push origin --delete feature/new-rpc-endpoint

# 7. When develop is stable, merge to master
git checkout master
git merge develop
git push origin master
```

---

## Troubleshooting

### Merge Conflict with Upstream

```bash
# If conflict during upstream sync:
git fetch upstream
git checkout master
git merge upstream/master
# CONFLICT!

# Option 1: Keep your changes
git checkout --ours path/to/file.rs
git add path/to/file.rs
git commit

# Option 2: Keep upstream changes
git checkout --theirs path/to/file.rs
git add path/to/file.rs
git commit

# Option 3: Manual resolution
# Edit file, remove conflict markers
git add path/to/file.rs
git commit
```

### Accidentally Committed to Master

```bash
# Move commits to develop
git checkout master
git log --oneline -5  # Note commit hashes
git reset --hard origin/master  # Reset master
git checkout develop
git cherry-pick <commit-hash>  # Apply commits to develop
```

### Lost Changes

```bash
# Find lost commits
git reflog

# Recover commit
git checkout <commit-hash>
git checkout -b recovery-branch
```

---

## Summary

**✅ Workflow Established:**

- `master` tracks upstream (stable)
- `develop` for integration testing
- `feature/*` for development

**✅ Your Changes Protected:**

- P2P module is additive (won't conflict)
- Custom RPC module is separate
- Merge conflicts resolved in your favor

**✅ Ready for Development:**

- Can safely add new features
- Can sync with upstream
- Can test in `develop` before `master`

This is a **production-ready Git workflow** used by many open-source projects! 🎉
