# Git Workflow

## Github Flow

We follow a standard [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow) methodology with additional [release branches](https://blog.bitsrc.io/git-branching-strategies-made-simple-af135de57000#c7ea).

It can be visualized like this:

```
            ---------
master     / topic   \
----------------------------------------->
    * v0.3.0-rc1    * v0.4.0-rc1
    * v0.3.0        | v0.4.0-rc2
                    ---------
                            * v0.4.0-rc2
                            * v0.4.0
                            | v0.4.1
                            -----------* v0.4.1
```

_note: "*" represents a tag and "|" represents a branch point._

_not shown: changes from branches v0.4.0-rc2 and v0.4.1 should be merged into master, if applicable._

### visualization, described

1. The `master` branch represents the tip of current development. It is an
   _integration_ branch, in the sense that developer changes from smaller
   _topic_ branches get merged and integrated into `master` and github's CI
   performs testing for every pull-request.

2. **Scenario 1 (v0.3.0 - Clean Release):** A release candidate (`v0.3.0-rc1`)
   is tagged from the `master` branch. Following testing, no significant issues
   are found, and the **same commit** is directly tagged as the final release
   (`v0.3.0`). This represents a smooth and efficient release where the first RC
   is deemed stable enough for production.

3. **Scenario 2 (v0.4.0 - Iterative Release Candidate Process):** A release
   candidate (`v0.4.0-rc1`) is tagged from the `master` branch. During testing,
   problems are identified. This necessitates further development and the
   creation of a subsequent release candidate (`v0.4.0-rc2`) on a branch derived
   from `v0.4.0-rc1`. After the issues are resolved in `v0.4.0-rc2`, the final
   release (`v0.4.0`) is tagged from that stable point.

4. **Patch Release (v0.4.1):** Following the stable release of `v0.4.0`, a bug
   or security issue is discovered. A patch release (`v0.4.1`) is created based
   on the `v0.4.0` tag to address this specific problem. This allows for a
   focused update to the stable release without incorporating new features or
   major changes that would warrant a minor version bump.  Note that a
   release-candidate is not employed in this example, as such patches should be
   small and there may be a high urgency.

5. **Topic Branch (`/ topic \`):** This represents a short-lived branch created
   from the `master` branch for the development of a specific feature or bug
   fix. Once the work on the topic is complete and tested, it is eventually
   merged back into the `master` branch, contributing to future release cycles.


### Branch policies:

#### master branch (aka trunk)

The master branch of each crate should always build and should always pass all
tests.

At present, any team member with repo write access may directly commit to the
`master` branch. However, now that neptune-core has launched Mainnet this policy
may soon be revised such that `master` will become locked so that all changes
must go through the pull-request process and be peer reviewed.

#### topic branches

Team members are encouraged to create a *topic* branch and pull-request for
larger changes or anything that might be considered non-obvious or
controversial.

tip: *topic* branches are sometimes called *feature* branches.

A *topic* branch typically branches off of `master` or another *topic* branch.
It is intended for an individual feature or bug-fix.  We should strive to keep
each *topic* branch focused on a single change/feature and as short-lived as
possible.

Third party contributors without repo write access must create a *topic* branch
and submit a pull request for each change.  This is accomplished by:
1. fork the repo
2. checkout and build the desired branch (usually master or a release branch)
3. create a topic branch
4. make your changes and commit them.
5. push your topic branch to your forked repo
6. submit the pull request.

##### Topic Branch Naming

When working on an open github issue, it is recommended to prefix the topic branch with the issue identifier.

When the branch is intended to become a pull request, it is recommended to add the suffix `-pr`.

If the branch exists in a triton/neptune official repo, (as opposed to a personal fork), then it is recommended to prefix with your github username followed by `/`.

So if working on issue `#232` and adding feature *walk-and-chew-gum* one might name the branch `myuser/232-walk-and-chew-gum-pr`.

### Testing policy (pre-release)

It is project policy that each major and minor release be tested as a
release-candidate on the main net prior to making an official release. Testing
on main net increases the likelihood that any unintended incompatibilities with
previous versions of the software are caught. And it tests the release-candidate
in an environment where reorganizations regularly occur.

It is an important period of integration testing "in the wild" for the release
candidate binary.  Operating on main net, it will necessarily be exposed to
peers running older versions of the software and may shake out issues that do
not occur with automated testing.

If resources allow, the release candidate should also be tested on a public
test net where it might be cheaper or easier to get test transactions included
in blocks.

#### Some specifics

1. The release candidate should be published using the same release process as
   the eventual release; see [releasing](releasing.md).
2. Each release candidate must be publicly announced with a dedicated topic in
   [talk.neptune.cash](https://talk.neptune.cash).
3. The release candidate should target 2 weeks of testing after the announcement
   on average with a minimum of 1 week.
4. The company behind neptune-cash will provide at least 1 dedicated machine for
   the public testnet for the purpose of running the release-candidate binary
   and composing blocks.  Of course the community is also encouraged to run
   nodes and mine (compose or guess) if possible.
5. A set of automated tests will be created that utilize the RPC API to perform
   automated transactions and test basic functionality of the live running
   nodes. These tests should/must be run at least once against each
   release-candidate binary while connected to the public testnet network.
6. If the release-candidate introduces breaking consensus changes, then a
   reset/restart of the testnet from the genesis block may be performed.
7. Patch releases may skip testnet testing if the risk seems low and/or the
   urgency is sufficiently high.


# neptune-core versioning and releases

## deviation from standard semver practice

neptune-core is presently both a (blockchain) library and a binary. Semantic versioning signals changes to APIs and mainly applies to libraries.  But it does not capture breaking changes that can occur in a blockchain ecosystem or breaking changes with regards to stored state, i.e. databases.

For blockchains it is of primary importance to maintain consensus and network
compatibility with other nodes on the network.

For these reasons, we define the version identifier as follows.

## version identifier

neptune-core uses sem-ver compatible identifier of the form:
```
<major>.<minor>.<patch>[-<candidate>]

where `candidate` is of the form "rc1", "rc2", etc and starts at 1.
```

Examples:
```
0.4.0-rc1
0.5.0-rc1
0.5.0-rc2
0.5.0-rc3
1.2.2
```

Non-Examples: (should not occur)
```
0.4.1-rc1       (point release should not be a release-candidate)
1.2.0-rc0       (release candidates start at 1, not 0)
```

note: for git tags, a "v" is prefixed, as per git convention.

Our release process treats these as:

**major**: bumped any time there are:

1. significant consensus or p2p layer changes. eg hard or soft-fork or breaking protocol change.
2. breaking library API changes.
3. breaking database changes.

resets minor and patch to 0.

**minor**: bumped any time changes from master are included in a release candidate.

resets patch to 0.

**patch**: bumped any time changes from a release branch are included in a release.

resets candidate to "-rc1".

**candidate**: added/bumped when a new public testnet is created for a candidate release.

*Note that the optional suffix is supported by cargo and related tools.*

## typical release

The normal/typical release flow would be:

1. normal changes (not consensus) are introduced in master.
2. a release candidate is tagged from master, eg `v0.3.0-rc1` and built.
3. The binary is launched on main net and connects with peers.
4. if significant problems are found then a new branch `v0.3.0-rc2` is created at `v0.3.0-rc1`, or possibly from master.  commit(s) are added. When ready, the final commit in the branch is tagged with `v0.3.0-rc2`, another instance launched, and so on.
5. fixes for the release-candidate should also be applied to master, if applicable.
6. After two weeks, or when team decides, the latest release-candidate tag is also tagged with `v0.3.0`, signifying an actual release.
7. The release is performed.

*note that by the time the release actually occurs, master may have diverged significantly.*

The release flow for a major version change is essentially the same except that the major version number is bumped and the minor version returns to 0.

Detailed release instructions are in [releasing.md](releasing.md).


## latest-release tag

The `master` branch may (but should, ideally not) contain changes that are not
compatible with previous release. Individuals looking for the latest release can
simply checkout the `latest-release` tag, which is updated as part of the
release process.

_note: End-users are discouraged from building and running the `master` branch
as it could result in undefined and unsupported states with regards to database
schemas, etc. It could even result in loss of funds or problems interacting with
peers due to concensus or p2p layer changes._


# Conventional Commits

It is preferred/requested that commit messages use the [conventional
commit](https://www.conventionalcommits.org/en/v1.0.0/) format.

This aids readability of commit messages and facilitates automated generation of
the ChangeLog.

For all but the most trivial changes, please provide some additional lines with
a basic summary of the changes and also the _reason/rationale_ for the changes.

A git template for assisting with creation of conventional commit messages can
be found in the [Git Message](git-message.md). This template can be added
globally to git with this command:

```
git config --global commit.template /path/to/neptune-core/docs/src/contributing/.gitmessage
```

It can also be added on a per-repository basis by omitting the `--global` flag.

## Cargo dependencies

### For published crate releases

When publishing a crate, and/or when making a release of `neptune-core`, all
dependencies should/must reference a version published to
[crates.io](https://crates.io).

In particular, git repo references must not be used.

### For development between crate releases.

Often parallel development will be occurring in multiple triton/neptune crates.
In such cases there may be API or functionality changes that necessitate
temporarily specifying a git dependency reference instead of a published
crates.io version.

For this, we keep the original dependency line unchanged, and add a crates.io
patch at the bottom of Cargo.toml.

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

A branch name is a moving target.  So if we were to specify a branch, then our
build might compile fine today and tomorrow it no longer does.

The [patch section docs](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#the-patch-section) have more detail.  In particular take note that:

1. Cargo only looks at the patch settings in the Cargo.toml manifest at the root of the workspace.
2. Patch settings defined in dependencies will be ignored.

This [blog article](https://gatowololo.github.io/blog/cargo-patch/) is also
helpful.


Finally, all such temporary patches must be removed before publishing a crate or
issuing a new release!
