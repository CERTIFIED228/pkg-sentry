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

## Why I made it

Scams aren't only fake websites. The apps and sites everyone uses are built out of thousands of free packages that developers download from PyPI (Python) and npm (JavaScript). Attackers publish malware dressed up as those packages, with names one typo away from popular ones (`reqeusts`, `crossenv`), or they take over real ones, and the code runs on the developer's machine the moment `pip install` or `npm install` finishes. From there it can steal passwords and keys, or end up inside software that ordinary people rely on. Registries remove these packages, but usually after people have already installed them.

pkg-sentry is a check you can run first.

## Download and try it

Needs Python 3.10 or newer. The only dependency is `packaging`.

```bash
pip install https://github.com/CERTIFIED228/pkg-sentry/releases/download/v0.1.1/pkg_sentry-0.1.1-py3-none-any.whl
pkg-sentry check requests reqeusts
```

The first one is the real `requests` and comes back OK. The second is a typo of it that nobody owns, which is exactly what an attacker would register, so it's flagged HIGH. On Windows, if `pkg-sentry` isn't recognised, run `python -m pkg_sentry` instead. Every version is on the [releases page](https://github.com/CERTIFIED228/pkg-sentry/releases).

## What it does

Give it a package name (or a whole project's dependency file) and it checks four things:

1. **Known malware.** Looks the package up on [OSV.dev](https://osv.dev), which collects the OpenSSF malicious-packages reports. Works even after the registry has deleted the package. npm's "security holding package" placeholders count too.
2. **The name.** Compared against the 15,000 most downloaded packages on each registry: one letter off (`colourama`), swapped letters (`reqeusts`), separators dropped (`crossenv` for `cross-env`), look-alike digits (`djang0`), `python3-` prefixes. A dependency that doesn't exist at all is flagged too, because anyone could register it (dependency confusion).
3. **The registry entry.** First published this week, a new release after years of silence (how hijacked accounts often look), a `99.9.9`-style version, no link to source code.
4. **The code.** Downloads the sdist and the wheel pip would pick on your machine (PyPI), or the tarball (npm), and reads it:
   - **Python** is parsed with `ast`, so renaming modules doesn't hide anything (`import base64 as b`, `__import__("base64")`, `getattr(__import__("builtins"), "exec")`). Files are decoded the way Python decodes them, so an encoding trick like UTF-7 can't hide a line inside a comment.
   - **JavaScript** is searched with comments removed (comment markers inside strings, regexes and template literals don't fool it), together with the `package.json` install hooks, the scripts they call through `npm run`, and `binding.gyp` commands.
   - Archives are read the way pip and npm read them, so a package can't show the scanner one thing and install another: every gzip member is read, npm tarballs lose the first folder of every entry whatever it's called, and a later copy of a file wins.
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
     - `.pth` files and `sitecustomize.py`, which run on every Python start;
     - compiled `.pyc` files that can't be read;
     - packages that republish themselves (spam and worms).

   Code it can't read (a file over the size limit, a damaged archive member) is reported, not skipped, so padding a package doesn't get it through.

## How it works

The package is downloaded into memory, opened the way pip or npm would open it, and read as text. Nothing from it is ever installed or run.

What matters most is *when* code runs. The same `subprocess` call means something different in `setup.py`, which runs during `pip install`, than inside a function nobody calls. So pkg-sentry works out what runs by itself:

- `setup.py`, build backends shipped inside the package, and the files they run or `exec`;
- modules `setup.py` imports (their top level runs) or calls into (their functions count too, one step deep, so a package's whole build toolchain doesn't look like install code);
- module-level code in anything inside a package (it runs on import);
- `if __name__ == "__main__"` blocks are left out;
- modules a `.pth` file imports, and modules in a wheel's `.data/purelib` folder (pip puts them straight into site-packages);
- npm install hooks, the scripts they call, and every file those `require`;
- tests, docs and CI scripts only count for signs that are never innocent.

### How the score works

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

### Keeping the scanner itself safe

The scanner reads hostile input, so it's careful with it:

- Nothing is ever installed, imported, executed or extracted to disk. Archives are read in memory.
- Every archive member is checked: no symlinks or hard links are followed, paths that climb out of the package (`../../.bashrc`) are reported rather than read, and there are limits on file count, file size, total size and compression ratio (zip bombs).
- If an archive carries on past the point where Python's tar reader stops (npm's reader goes further), it's reported as not fully read instead of passing as clean.
- Deeply nested code can't crash the scan (that alone would be a way to hide a payload): the syntax tree is walked without recursion, and if Python can't parse a file at all, the text checks still run on it. Python 3.10 itself crashes on a long enough `1 + 1 + ...` chain, so on 3.10 the file is measured with the tokenizer before it's parsed.
- Downloads are capped at 100 MB by default, stop reading if a server lies about the size, and a download that's cut off is an error rather than a smaller file.
- Registry metadata is type-checked rather than trusted, since publishers control most of it.
- Text from the package is printed with control characters escaped, so a snippet can't use terminal escape codes to wipe the warning and print a fake "OK".
- One runtime dependency, and HTTP is plain `urllib`. A supply-chain tool with a big dependency tree would be a bit ironic.

## Using it

```bash
# one or more packages
pkg-sentry check requests
pkg-sentry check requests==2.31.0 npm:lodash@4.17.21 @babel/core
pkg-sentry check --npm express react

# every dependency of a project (requirements files and their -r includes,
# pyproject.toml including Poetry, package.json, package-lock.json)
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
| `--no-code` | registry and name checks only, nothing downloaded (npm install scripts are still read from the registry) |
| `--max-download MB` | biggest file to download and read (default 100) |

Exit codes: `0` nothing at or above `--fail-on`, `1` something is, `2` something couldn't be checked or was only partly checked. A package too big to download is reported as "partly checked", never as OK. That makes it easy to put in CI: [docs/github-action.md](docs/github-action.md) has a workflow that blocks pull requests adding a bad dependency.

## How accurate it is

Measured with [scripts/benchmark.py](scripts/benchmark.py) on:

- **Real malware:** 5,148 releases from Datadog's [malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset): 2,248 from PyPI and a random 2,900 from npm. That includes packages published as malware and hijacked releases of real packages.
- **Popular packages:** the 1,000 most downloaded on each registry.

Only the name and code checks are measured. The known-malware lookup would recognise most of the samples, which wouldn't say anything about the rules.

To keep this honest, the data was split:

- **Tuning set:** malware discovered before 2025, and half of the popular packages.
- **Test set:** malware from 2025-2026 and the other half of the popular packages. This is what's reported here, and the rules were never adjusted on it.

Each popular package is read the way `pkg-sentry check` reads it: the sdist and the wheel separately, npm tarballs the npm way.

Results on the test set:

| | Malware rated medium or worse | Popular packages rated medium or worse |
|---|---|---|
| PyPI | 68.4% of 567 | 3.7% of 511 |
| npm | 65.6% of 2,462 | 0.4% of 511 |
| **Both** | **66.2%** of 3,029 (36.1% critical) | **2.1%** of 1,022 (none critical) |

On the tuning set the same code catches 86.3% of the malware (85.2% PyPI, 90.2% npm) with 1.5% false alarms. The gap is the point of keeping a test set: newer malware uses tricks the rules weren't shaped around, so 66% is the honest number to expect on malware nobody has seen yet. The test set was also run once before the two code reviews, when it scored 63.9%. Everything changed since then came from the reviews and the tuning set, not from test results.

The popular packages flagged on the test set really do things malware does, as part of their job: debugpy ships a DLL injector, execnet runs code that arrives over a socket, cmake's build backend downloads and runs a build, and huggingface-hub has a webhook.site URL and PowerShell installer commands in its code. The report shows the file and line for each, so a person can tell.

Things to keep in mind:

- Most samples in the dataset were found by Datadog's own scanner, [GuardDog](https://github.com/DataDog/guarddog), which looks for similar things. Malware written to dodge these rules would do better than this suggests.
- Some samples aren't malware you could ever detect from their code. Some are spam packages, some are empty placeholders, and some do nothing harmful themselves but depend on another malicious package.
- "Medium" on a popular package isn't necessarily wrong. A package that downloads and runs a binary while installing is worth knowing about, even when it's esbuild.

## Limitations

- JavaScript is searched, not parsed. Heavily minified code and tricks like building `require` names at runtime can hide calls.
- Only the files pip or npm would fetch are read. Malicious code downloaded later, or pulled in through a dependency, is only caught if that dependency is checked too (`scan` on a lockfile does that).
- For PyPI, only the wheel for your own platform is read. A package could ship a clean Linux wheel and a malicious Windows one, and checking it on Linux wouldn't see the Windows one.
- Compiled code (`.so`, `.pyd`, `.node`, `.pyc`) can't be read. `.pyc` files and dropped programs are flagged; native extensions aren't, because so many honest packages have them.
- The popular-package lists are a snapshot. Rebuild them with `python scripts/build_data.py`.
- A determined attacker who reads these rules can write around them. Static checks raise the cost of an attack; they don't make it impossible.

## Development

```bash
git clone https://github.com/CERTIFIED228/pkg-sentry.git
cd pkg-sentry
python -m venv .venv
.venv\Scripts\activate          # Windows; on macOS/Linux: source .venv/bin/activate
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
