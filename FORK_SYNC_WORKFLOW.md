# Neptune Core Fork Sync Workflow

## Repository Setup

### Remotes Configuration
```bash
origin      https://github.com/seaoffreedom/neptune-core.git (your fork)
upstream    https://github.com/Neptune-Crypto/neptune-core.git (official repo)
```

### Branches
- `master` - stays in sync with upstream
- `feature/rpc-server-wallet-integration` - your custom RPC server changes

## Custom Changes Summary

All custom changes are isolated to `neptune-core-cli/` directory:

### Added Files
- `COMMANDS_REFERENCE.md` - CLI command documentation
- `JSON_RPC_USAGE.md` - JSON-RPC usage guide
- `MANUAL_TESTING_GUIDE.md` - Testing procedures
- `RPC_INTEGRATION_GUIDE.md` - Integration documentation
- `WALLET_INTEGRATION_TEST.md` - Wallet integration tests
- `docs/RPC_FLOW_DIAGRAM.md` - RPC flow diagrams
- `test-rpc-endpoints.sh` - Testing script
- `src/rpc/handlers.rs` - RPC request handlers (1820 lines)
- `src/rpc/mod.rs` - RPC module definitions
- `src/rpc/server.rs` - HTTP JSON-RPC server
- `src/rpc/server_old.rs` - Legacy server implementation

### Modified Files
- `Cargo.toml` - Added HTTP dependencies
- `src/main.rs` - Integrated RPC server, added get-cookie command

### Key Features
1. HTTP JSON-RPC server for wallet integration
2. Cookie-based authentication (compatible with neptune-core)
3. Wallet-friendly RPC endpoints (send, receive, balance, etc.)
4. Large bech32m address support (8KB buffer)

## Staying in Sync with Upstream

### 1. Fetch Latest Upstream Changes
```bash
cd /home/anon/Documents/GitHub/neptune-core
git fetch upstream
git fetch origin
```

### 2. Update Master Branch
```bash
git checkout master
git merge upstream/master
git push origin master
```

### 3. Rebase Feature Branch on Latest Master
```bash
git checkout feature/rpc-server-wallet-integration
git rebase master

# If conflicts occur:
# - Resolve conflicts in neptune-core-cli/ files
# - git add <resolved-files>
# - git rebase --continue

git push origin feature/rpc-server-wallet-integration --force-with-lease
```

## Cherry-Picking Upstream Changes

### Identify Useful Upstream Commits
```bash
# View new commits in upstream
git log master..upstream/master --oneline

# Check if any affect neptune-core-cli
git log master..upstream/master --oneline -- neptune-core-cli/
```

### Cherry-Pick Specific Commits
```bash
git checkout feature/rpc-server-wallet-integration
git cherry-pick <commit-hash>

# Or cherry-pick a range
git cherry-pick <start-hash>^..<end-hash>
```

## Merging Upstream Branches

### For Non-Conflicting Changes
```bash
git checkout feature/rpc-server-wallet-integration
git merge upstream/<branch-name>
```

### For Specific Features
```bash
# Merge only files that don't conflict with your changes
git checkout feature/rpc-server-wallet-integration
git merge upstream/<branch-name> --no-commit

# Review changes
git status

# If conflicts in your custom files, keep your version:
git checkout --ours neptune-core-cli/src/rpc/

# Complete the merge
git commit
```

## Testing After Sync

### Build and Test
```bash
cargo build --release
cargo test

# Test RPC server
cd neptune-core-cli
./test-rpc-endpoints.sh
```

### Verify Custom Functionality
1. Start neptune-core daemon
2. Start neptune-cli RPC server: `neptune-cli --rpc-mode`
3. Test wallet integration endpoints
4. Verify cookie authentication works

## Conflict Resolution Strategy

### neptune-core-cli Conflicts
- **Always keep your custom RPC implementation**
- Review upstream changes for:
  - Bug fixes → integrate if applicable
  - New CLI commands → add to RPC handlers if needed
  - Security updates → prioritize integration

### Other Conflicts
- Upstream changes outside neptune-core-cli should be accepted
- Only modify if it breaks your RPC server integration

## Regular Maintenance

### Weekly
```bash
# Update master
git checkout master
git fetch upstream
git merge upstream/master
git push origin master
```

### Monthly
```bash
# Rebase feature branch
git checkout feature/rpc-server-wallet-integration
git rebase master
git push origin feature/rpc-server-wallet-integration --force-with-lease
```

## Emergency: Reset to Upstream

If your fork gets too out of sync:

```bash
# Backup your RPC changes
cp -r neptune-core-cli /tmp/neptune-core-cli-backup

# Reset to upstream
git checkout master
git reset --hard upstream/master
git push origin master --force

# Recreate feature branch
git checkout -b feature/rpc-server-wallet-integration-new
cp -r /tmp/neptune-core-cli-backup/* neptune-core-cli/
git add neptune-core-cli/
git commit -m "feat: restore RPC server implementation"
git push origin feature/rpc-server-wallet-integration-new
```

## Notes

- Your RPC server is fully contained in neptune-core-cli
- Upstream rarely modifies neptune-cli, minimizing conflicts
- When conflicts occur, they're usually in Cargo.toml or main.rs
- Always test RPC functionality after any upstream merge

