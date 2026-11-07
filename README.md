# pkg-sentry

[![CI](https://github.com/CERTIFIED228/pkg-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/CERTIFIED228/pkg-sentry/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-1-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Checks PyPI and npm packages for signs of malware **before** you install them. It never installs or runs anything: the package is downloaded into memory and read like text.

```console
$ pkg-sentry check bytesp==99.7
bytesp==99.7 (PyPI)  CRITICAL 100/100
  - decodes hidden code and runs it  [bytesp-99.7.tar.gz/setup.py:12]
      exec(base64.b64decode(code))
  - replaces the 'install' command with its own code  [bytesp-99.7.tar.gz/setup.py:21]
      'install'
  - version 99.7 is the kind used to win over a company's internal package (dependency confusion)
```

Attackers publish packages with names one typo away from popular ones (`reqeusts`, `crossenv`), or take over real ones, and the code runs on your machine the moment `pip install` or `npm install` finishes. Registries remove them, but usually after people have installed them.

## What it checks

1. **Known malware.** Looks the package up on [OSV.dev](https://osv.dev), which collects the OpenSSF malicious-packages reports. Works even after the registry has deleted the package. npm's "security holding package" placeholders count too.
2. **The name.** Compared against the 15,000 most downloaded packages on each registry: one letter off (`colourama`), swapped letters (`reqeusts`), separators dropped (`crossenv` for `cross-env`), look-alike digits (`djang0`), `python3-` prefixes. A dependency that doesn't exist at all is flagged too, because anyone could register it (dependency confusion).
3. **The registry entry.** First published this week, a new release after years of silence (how hijacked accounts often look), a `99.9.9`-style version, no link to source code.
4. **The code.** Downloads the sdist and wheel (PyPI) or the tarball (npm) and reads it:
   - **Python** is parsed with `ast`, so renaming modules doesn't hide anything (`import base64 as b`, `__import__("base64")`, `getattr(__import__("builtins"), "exec")`).
   - **JavaScript** is searched with comments removed, together with the `package.json` install hooks.
   - It looks for what real malware does:
     - decoding hidden code and running it;
     - downloading and running programs;
     - reading browser passwords, Discord tokens or crypto wallets;
     - sending data to webhooks, Telegram bots, ngrok or bare IP addresses;
     - dumping environment variables;
     - hidden PowerShell;
     - setting itself up to start again later;
     - obfuscated code;
     - programs disguised as images;
     - `.pth` files that run on every Python start;
     - packages that republish themselves (spam and worms).

What matters most is *when* code runs. The same `subprocess` call means something different in `setup.py`, which runs during `pip install`, than inside a function nobody calls. So pkg-sentry works out what runs by itself:
- `setup.py` and the local modules it imports;
- module-level code in anything inside a package (it runs on import);
- `if __name__ == "__main__"` blocks are left out;
- npm install hooks and the files they start;
- tests, docs and CI scripts only count for signs that are never innocent.

## Install

Needs Python 3.10+. The only dependency is `packaging`.

```bash
pip install git+https://github.com/CERTIFIED228/pkg-sentry.git
```

or from a clone: `pip install -e .`

## Usage

```bash
# one or more packages
pkg-sentry check requests
pkg-sentry check requests==2.31.0 npm:lodash@4.17.21 @babel/core
pkg-sentry check --npm express react

# every dependency of a project
pkg-sentry scan requirements.txt
pkg-sentry scan package-lock.json --all     # --all also lists the clean ones

# something you've already downloaded (pip download x --no-deps, npm pack x)
pkg-sentry inspect suspicious-1.0.tar.gz
pkg-sentry inspect ./unpacked-folder
```

| Option | |
|---|---|
| `--json` | machine-readable output |
| `--fail-on LEVEL` | exit with 1 if anything is at least `low`, `medium`, `high` (default) or `critical` |
| `--offline` | skip the OSV.dev lookup |
| `--no-code` | registry and name checks only, nothing downloaded |

Exit codes: `0` nothing at or above `--fail-on`, `1` something is, `2` something couldn't be checked. That makes it easy to put in CI: [docs/github-action.md](docs/github-action.md) has a workflow that blocks pull requests adding a bad dependency.

## How the score works

Every finding has points. Each kind of finding counts once, however many files it appears in, and the rest stay as evidence in the report.

Findings come in two kinds:

- **Behaviour** is what honest packages do too: an install script, network access or shell commands during install, shipping an `.exe`, a brand-new package. esbuild downloads and runs a binary when it's installed, and so do a lot of malware droppers. Behaviour alone is capped at 45 points, so it can reach medium but never high.
- **Evidence** is hard to explain innocently: decoding hidden code and running it, a Discord webhook, reading browser passwords, obfuscation, a typosquatted name. Evidence adds up without a cap.

| Severity | Score | Meaning |
|---|---|---|
| Critical | 90+ | known malware, or something that's never innocent at install time (decoding and running hidden code in `setup.py`, sending data to a webhook during install) |
| High | 60+ | behaviour plus evidence, or several kinds of evidence |
| Medium | 35+ | worth a look before installing |
| Low | 15+ | minor signs |

## Safety

The scanner reads hostile input, so it's careful with it:

- Nothing is ever installed, imported, executed or extracted to disk. Archives are read in memory.
- Every archive member is checked: no symlinks or hard links are followed, paths that climb out of the package (`../../.bashrc`) are reported rather than read, and there are limits on file count, file size, total size and compression ratio (zip bombs).
- A file deep enough to crash Python's parser doesn't crash the scan (that alone would be a way to hide a payload); it falls back to the text checks.
- Downloads are capped at 50 MB and stop reading if a server lies about the size.
- One runtime dependency, and HTTP is plain `urllib`. A supply-chain tool with a big dependency tree would be a bit ironic.

## How accurate it is

Measured with [scripts/benchmark.py](scripts/benchmark.py) on:

- **Real malware:** a sample of Datadog's [malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), every human-confirmed malicious PyPI package plus 2,900 npm ones.
- **Popular packages:** the 1,000 most downloaded on each registry.

Only the name and code checks are measured. The known-malware lookup would recognise most of the samples, which wouldn't say anything about the rules.

To keep this honest, the data was split:

- **Tuning set:** malware discovered before 2025, and half of the popular packages.
- **Test set:** malware from 2025-2026 and the other half of the popular packages. This is what's reported here, and the rules were never adjusted on it.

BENCHMARK_TABLE

Things to keep in mind:

- Most samples in the dataset were found by Datadog's own scanner, [GuardDog](https://github.com/DataDog/guarddog), which looks for similar things. Malware written to dodge these rules would do better than this suggests.
- Some samples aren't malware you could ever detect from their code. Some are spam packages, some are empty placeholders, and some do nothing harmful themselves but depend on another malicious package.
- "Medium" on a popular package isn't necessarily wrong. A package that downloads and runs a binary while installing is worth knowing about, even when it's esbuild.

## Limitations

- JavaScript is searched, not parsed. Heavily minified code and tricks like building `require` names at runtime can hide calls.
- Only the files pip or npm would fetch are read. Malicious code downloaded later, or pulled in through a dependency, is only caught if that dependency is checked too (`scan` on a lockfile does that).
- The popular-package lists are a snapshot. Rebuild them with `python scripts/build_data.py`.
- A determined attacker who reads these rules can write around them. Static checks raise the cost of an attack; they don't make it impossible.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

To reproduce the benchmark:

```bash
git clone https://github.com/DataDog/malicious-software-packages-dataset
python scripts/fetch_popular.py popular --count 1000
python scripts/benchmark.py --malware malicious-software-packages-dataset --benign popular
```

The samples are real malware (encrypted zips, password `infected`). The benchmark only ever reads them into memory, but don't unzip them on a machine you care about.

## Data

- `src/pkg_sentry/data/top-pypi.txt`: from [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages)
- `src/pkg_sentry/data/top-npm.txt`: from [npm-high-impact](https://github.com/wooorm/npm-high-impact)
- Known malware: [OSV.dev](https://osv.dev) and the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) reports in it
- Benchmark malware: [Datadog Security Labs](https://github.com/DataDog/malicious-software-packages-dataset) (Apache-2.0)
