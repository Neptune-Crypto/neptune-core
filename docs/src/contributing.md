## Contributing

Instructions and helpful information for people who want to contribute.

### Regression Tests

If you think you've found a bug in `neptune-core` and want to submit a fix, please try to include a **regression test** alongside your code changes.

**What is a regression test?**
It is a test specifically designed to reproduce the bug you found. Its goal is to act as a safeguard, ensuring that future updates to the codebase don't accidentally bring this exact same bug back (causing the code to "regress"). Its goal is also
to prove to other developers that the bug is real and not imagined.

**How to verify your test:**
A good regression test proves that your code actually solves the problem. You can verify this in two steps:
1. Run your new test *before* applying your fix. **The test should fail.**
2. Apply your fix and run the test again. **The test should pass.**

Including this proof gives reviewers confidence that the issue is real, is fully resolved, and will stay fully resolved!
