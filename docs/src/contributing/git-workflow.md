# Git Workflow

## Github Flow

We follow a standard [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow) methodology with additional [release branches](https://blog.bitsrc.io/git-branching-strategies-made-simple-af135de57000#c7ea).

It can be visualized like this:

```
master
-------*----------------------*>
 \             --------
  \  dev      / topic  \
   ----*----------------------*--------------->
        \ release              \ release
        ------------------>    --------->
        \ hotfix /
        --------
```

### master branch (aka trunk)

The `master` branch represents the tip of current development. It is an _integration_ branch, in the sense that developer changes from smaller _topic_ branches get merged and integrated into `master` and github's CI performs testing for every pull-request.

The master branch of each crate should always build and should always pass all tests.

At present, any team member with repo write access may directly commit to the `master` branch. However, as we get closer to a mainnet launch, `master` should/will become locked so that all changes must go through the pull-request process and be peer reviewed.

### topic branches

Even now, team members are encouraged to create a *topic* branch and pull-request for larger changes or anything that might be considered non-obvious or controversial.

tip: *topic* branches are sometimes called *feature* branches.

A *topic* branch typically branches off of `master` or another *topic* branch.  It is intended for an individual
feature or bug-fix.  We should strive to keep each *topic* branch focused on a single change/feature and as short-lived as possible.

Third party contributors without repo write access must create a *topic* branch and submit a pull request for each change.  This is accomplished by:
1. fork the repo
2. checkout and build the desired branch (usually master or a release branch)
3. create a topic branch
4. make your changes and commit them.
5. push your topic branch to your forked repo
6. submit the pull request.

#### Topic Branch Naming

When working on an open github issue, it is recommended to prefix the topic branch with the issue identifier.

When the branch is intended to become a pull request, it is recommended to add the suffix `_pr`.

If the branch exists in a triton/neptune official repo, (as opposed to a personal fork), then it is recommended to prefix with your github username follwed by `/`.

So if working on issue `#232` and adding feature *walk_and_chew_gum* one might name the branch `myuser/232_walk_and_chew_gum_pr`.

### release branch

The `master` branch can contain changes that are not compatible with whatever network is currently live. Beta-testers looking for the branch that will synchronize with the network that is currently live need branch `release`. This branch may cherry-pick commits that are meant for `master` so long as they are backwards-compatible. However, when this task is too cumbersome, branch `release` will become effectively abandoned -- until the next network version is released.

#### TestNet Release Protocol

 - Ensure that master builds against crates that live on [crates.io](https://crates.io). In particular, no dependencies on github repositories or revisions.
 - Update `README.md` in case to make sure the installation instructions are up-to-date.
 - Ensure that all tests pass.
 - Bump the version in `Cargo.toml`
 - Create a commit with the subject line `v0.0.6` (or watever the new version number is) and in the body list all the changes.
 - Push to `master` on github.
 - Add a tag marking the current commit with the version:
   - `git tag v0.0.6` (or whatever the next version is)
   - `git push --tags`.
 - Set branch `release` to point to `master`:
   - `git checkout release`
   - `git reset master`
   - `git push`
 - Consider making an announcement.

# Conventional Commits

It is preferred/requested that commit messages use the [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/) format.

This aids readability of commit messages and facilitates automated generation of the ChangeLog.

For all but the most trivial changes, please provide some additional lines with a basic summary of the changes and also the _reason/rationale_ for the changes.

A git template for assisting with creation of conventional commit messages can be found in the [Git Message](contributing/git-message.md). This template can be added globally to git with this command:

```
git config --global commit.template /path/to/neptune-core/docs/src/contributing/.gitmessage
```

It can also be added on a per-repository basis by omitting the `--global` flag.

## Cargo dependencies

### For published crate releases

When publishing a crate, and/or when making a release of `neptune-core`, all dependencies should/must reference a version published to [crates.io](https://crates.io).

In particular, git repo references must not be used.

### For development between crate releases.

Often parallel development will be occurring in
multiple triton/neptune crates.  In such cases
there may be API or functionality changes that necessitate temporarily specifying a git dependency reference instead of a published crates.io version.

For this, we keep the original dependency line unchanged, and add a crates.io patch at the bottom of Cargo.toml.

Example:

```
[dependencies]
tasm-lib = "0.2.1"

[patch.crates-io]
# revision  "f711ae27" is tip of tasm-lib master as of 2024-01-25
tasm-lib = { git = "https://github.com/TritonVM/tasm-lib.git", rev = "f711ae27" }
```

Note that:
1. `tasm-lib = "0.2.1"`.  We do not use `{git = "..."}` here.
2. We specify a specific revision, rather than a branch name.
2. We place a comment indicating the branch on which the
revision resides, as of placement date.

A branch name is a moving target.  So if we were to specify a branch, then our build might compile fine today
and tomorrow it no longer does.

The [patch section docs](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#the-patch-section) have more detail.  In particular take note that:

1. Cargo only looks at the patch settings in the Cargo.toml manifest at the root of the workspace.
2. Patch settings defined in dependencies will be ignored.

This [blog article](https://gatowololo.github.io/blog/cargo-patch/) is also helpful.


Finally, all such temporary patches must be removed before publishing a crate or issuing a new release!
