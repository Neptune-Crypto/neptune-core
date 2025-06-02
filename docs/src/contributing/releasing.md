# Releasing Neptune Core

This section describes the steps to publish a new version of Neptune Core, and to release & distribute its binary artifacts.

## Automation

This is presently a largely manual process.  It is expected/encouraged that one
or more custom deployment tools will be developed so this becomes a push-button
process instead, or even fully automated when certain event(s) happen.  Such a
tool will remove tedium as well as the human error factor, which is important
for performing the task regularly and consistently.

## Release Candidate vs Release.

Review the distinction [here](git-workflow.md), and make sure you know which is being generating and what the correct version should be.

A release should typically be performed two weeks after the matching
release-candidate has begun testing in testnet, though circumstances might
dictate otherwise. Also patch releases (major and minor version unchanged) can
be an exception.

## Pre-requisites

The following tools are used to ensure a high quality release.

- [cargo-binstall](https://github.com/cargo-bins/cargo-binstall) – Faster installation of the needed tools (optional)
- [cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks/) – Scans the crate for [semver](https://semver.org/) violations
- [git cliff](https://git-cliff.org/docs/) – Simplifies changelog creation
- [cargo-release](https://github.com/crate-ci/cargo-release) – Simplifies simultaneous publication of multiple crates
- [dist](https://opensource.axo.dev/cargo-dist/book/introduction.html) – Creates installers and publishes them in a [GitHub release](https://github.com/Neptune-Crypto/neptune-core/releases)

Use the following commands to install the needed tools.
If you decide against using `cargo binstall`, it's generally possible to just `cargo install` instead.
Some tools might require `cargo install --locked`.

```sh
cargo install cargo-binstall
cargo binstall cargo-semver-checks
cargo binstall git-cliff
cargo binstall cargo-release
cargo binstall cargo-dist
```

## Release Process Checklist

Not every step of the release process is (or should be) fully automated.
An example of a semi-automated step is changelog generation.
Tools like `git cliff` help, but a manual edit is necessary to reduce noise and achieve the polish appreciated by readers of the changelog.
An example of a fully automated step is assembly and distribution of binaries by `dist`.

### Set Working Directory to Workspace Root

Unless indicated otherwise, the current working directory is assumed to be the workspace root.

```sh
cd /path/to/neptune-core
```

### Check Distribution Workflow Files

Run [`dist init`](https://opensource.axo.dev/cargo-dist/book/quickstart/rust.html#adding-installers) to generate the latest GitHub workflow files that will take care of binary distribution.
The interface allows to add or remove target platforms as well as installers.
Feel free to change those settings, but be aware that not all installers are equally well supported; you might want to inform yourself before changing anything.

Usually, the generated GitHub workflow files are identical to the existing ones.
In this case, move on to the next step.
If the workflow files have changed, commit them.
An appropriate commit message could be:
`ci: Update release workflow files`

### Bump Version

Bump the version in `Cargo.toml` [as appropriate](git-workflow.md#version_identifier)

See also: https://doc.rust-lang.org/cargo/reference/semver.html.


### Confirm Version Bump as Semantic

> ℹ️ Because binaries cannot be used as a dependency, this step is only relevant if Neptune Core has library targets.
<!---
    At the time of writing, there are no library targets.
    Remove the note above if there is a library target.
    Remove every mention to `cargo-semver-checks` if it is certain that Neptune Core will never have library targets.
--->

Make sure that the version bump conforms to semantic versioning.

```sh
cargo semver-checks
```

### Generate Changelog Addition

Summarize the changes introduced since the last version.
Consistent use of [Conventional Commits](https://www.conventionalcommits.org) and `git cliff` get you started:

```sh
git cliff v0.0.1..HEAD -t vX.Y.Z > /tmp/change_diff.md
#         ~~~~~~~          ~~~~~~
#            |             the to-be-released version
#            |
#         at least 2 versions back for the GitHub “compare” link to work
```

If new commit types were introduced since the last release, `git cliff` will not know about them.
You can recognize the commit types unknown to `git cliff` by the missing associated emoji in the corresponding headline in the generated changelog addition.
Add the new commit types to `cliff.toml` and rerun the above command.

### Polish the Changelog Addition

Make the changelog addition (`/tmp/change_diff.md`) concise.
This is a manual step.

Feel free to delete entries generously.
For example, a branch that builds up to a certain feature might have a series of commits that are relevant for development and review.
Users of Neptune Core probably only care about the feature itself;
they should not be bombarded with minute details of its development process.
Should they be interested in more details, the changelog will have a link to the commit that introduced the feature.
From there, they can start their own journey of discovery.

If you find an entry in the changelog addition confusing or irrelevant, then with high probability, so will users of Neptune Core;
delete the changelog entry, or investigate its meaning and rewrite it.

Focus only on the new version, even though the changelog addition contains sections for older versions.
The changelogs for those older versions are already in the `CHANGELOG.md`, and should probably not be touched.

### Amend `CHANGELOG.md`

Copy the now-polished changelog addition from `/tmp/change_diff.md` into `CHANGELOG.md`.

### Commit

Add and commit the changed files.

```sh
git add Cargo.toml
git add CHANGELOG.md
git commit -m "chore: Release vX.Y.Z"
#                              ~~~~~
#                              the new version
```

### Ensure that Tests Pass

Make sure all tests pass, preferably by waiting for [GitHub's CI](https://github.com/Neptune-Crypto/neptune-core/actions) to finish.
Alternatively, run them locally:

```sh
cargo test --all-targets
```

### Publish to `crates.io`

The tool `cargo-release` helps to publish multiple, possibly inter-depending crates with a single command.

> ℹ️ If the workspace has only one member, `cargo publish` (instead of `cargo release`) works fine.
>    With `cargo publish`, you will need to create git tags manually.
<!---
    At the time of writing, the Neptune Core workspace has only one member crate.
    Remove the note above if there is more than one workspace member.
    Remove every mention to `cargo-release` if it is certain that Neptune Core will always have only one workspace member.
--->

```sh
cargo release --execute --no-push
#             ~~~~~~~~~ ~~~~~~~~~
#                 |     gives you time to review the created git tag(s)
#                 |
#             omit this to get a dry run
```

### Get Green Light from Continuous Integration

Create a new git branch with the release commit and push it to GitHub.
Open a pull request from that branch.
Wait for continuous integration to do its job.

Once CI gives the green light, fast-forward the master branch to the tip of the feature branch and push it.

### Push Tag to GitHub

In a previous step, `cargo-release` automatically created one or multiple git tags.
Edit them until you are happy, then push the tag(s) to GitHub.

 - To show tags: `git tag --list`
 - To push a tag: `git push origin [tag_name]`

### If a release-candidate:

#### Deploy release to testnet machine(s).

(full instructions: TBD)

Announce the release-candidate in a post at talk.neptune.cash.

Ensure that a composer is running using the release-candidate binary.

### If an actual release:

#### Set tag `latest-release`

The tag `latest-release` should always point to the commit for the *latest
release*.

*note: never a release-candidate, eg ".rc1".*

```
git tag --force latest-release
git push --force origin latest-release
```

#### Consider updating social media

  Announce the release in a post at talk.neptune.cash.

  telegram, twitter/x, reddit.com/r/cryptocurrencies,
  reddit.com/r/neptune-cash, etc.


### Check Release Artifacts & Page

Pushing the git tag(s) triggers CI once more.
After [CI has done its job](https://github.com/Neptune-Crypto/neptune-core/actions), check the [release page](https://github.com/Neptune-Crypto/neptune-core/releases) to see if everything looks okay.

> 🎉 Congrats on the new release!
