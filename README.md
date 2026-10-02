# MagAudit dependency check

A free GitHub Action that looks at the dependencies a pull request **adds** and flags two
things before they merge:

- **The package does not exist** in PyPI or npm. Either an assistant invented the name, or the
  name is unclaimed and anyone can register it.
- **The package exists but is brand new and barely used**: published less than 30 days ago, or
  less than 90 days ago with under 1,000 weekly downloads (when the download counter answers;
  if it does not, only the 30-day rule applies). That is the profile of a malicious package in
  the days before any advisory exists.

It runs entirely in your runner. **Your code never leaves it**, and no AI model is involved.

## Use it

```yaml
name: Dependency check
on: pull_request

permissions:
  contents: read

jobs:
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # the check compares the pull request with its base branch
      - uses: MagSolutionsAI/dependency-check@v1
```

Findings appear as annotations on the changed line and in the job summary. By default the
check fails when it finds either of the two cases above; make it a required check in your
branch protection and it blocks the merge.

| Input | Default | What it does |
|---|---|---|
| `fail-on` | `high` | `high`: fail on missing and brand-new packages. `critical`: fail only on missing ones. `none`: annotate, never fail. |

## What it reads

`requirements*.txt`, `pyproject.toml`, `Pipfile` and `package.json`, and only the lines the pull
request adds. A version bump of a package you already had is not a new dependency. It also
reads the `pyproject.toml` and `package.json` files across your repository, so it does not
flag packages your own repository defines, or installs from a local path or from git.

## Where data goes

Only package names leave the runner:

| Destination | What for |
|---|---|
| `pypi.org`, `registry.npmjs.org` | Does the package exist, and when was it first published |
| `api.npmjs.org` | Weekly downloads of an npm package |
| `pypistats.org` | Weekly downloads of a Python package, only when it is less than 90 days old (PyPI does not publish download counts) |

Nothing is sent to us. The action installs one package, `requests`, from PyPI.

## What it does not do

- It does not analyse what a package does (install scripts, network access, obfuscated code).
  [Socket](https://socket.dev) does that, and its free plan blocks malicious dependencies.
- It does not read lockfiles, and it does not look up known vulnerabilities.
- A registry check is a point in time: a name that does not exist today can be registered in
  an hour.
- It does not scan your code for leaked keys or unsafe configuration. The
  [MagAudit GitHub App](https://magsolutionsai.com/) does, in the same pull request comment.

## How often it is wrong

We measured it before publishing, on 28 September 2026, against 44 real public pull requests
that added 305 dependencies:

- The action extracted **exactly the same dependencies** as the MagAudit App in all 44.
- The App raised 2 alarms, and **both were false**: a package the repository itself defines,
  and one it installs from git. The action, which also reads the repository's own manifests,
  raised **none**.

The sample contained no real malicious package, so this measures false alarms, not detection.
Detection is covered by tests built from real cases.
