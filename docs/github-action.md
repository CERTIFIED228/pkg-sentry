# Blocking bad dependencies in pull requests

Save this as `.github/workflows/dependencies.yml` in your own project. When a
pull request changes a dependency file, pkg-sentry checks every package in it
and the check fails if anything is rated high or critical.

```yaml
name: dependencies

on:
  pull_request:
    paths:
      - "requirements*.txt"
      - "pyproject.toml"
      - "package.json"
      - "package-lock.json"

jobs:
  pkg-sentry:
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      # Pin a release tag or commit so the check can't change under you.
      - run: pip install git+https://github.com/CERTIFIED228/pkg-sentry.git@v0.1.0
      # Use whichever files your project has. Exit code 1 fails the check.
      - run: pkg-sentry scan requirements.txt
      - run: pkg-sentry scan package-lock.json
```

Exit code 2 means a package couldn't be fully checked (too big to download,
or the registry was down). It fails the step too, because an unchecked
package isn't a passed one.

`--fail-on medium` makes it stricter. `--json > report.json` gives a file you
can upload as a build artifact.

pkg-sentry never installs or runs the packages it checks, so it's safe to run
on a pull request from someone you don't know.
