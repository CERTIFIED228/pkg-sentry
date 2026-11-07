"""Is this name a near-copy of a popular package?

Typosquats rely on someone mistyping `pip install`/`npm install`, so the
only names worth copying are popular ones. A candidate is compared against
the most downloaded packages, and a name that's popular itself is never
flagged.
"""

import re
from dataclasses import dataclass
from functools import cache
from importlib import resources

from .spec import normalise

# Only the top of the list is worth squatting. Below that, distance-1
# neighbours are mostly unrelated real projects.
TARGETS = 5000
AFFIX_TARGETS = 500
MIN_LENGTH = 5

LOOKALIKES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
PREFIXES = ("python-", "python3-", "py-", "node-")
SUFFIXES = ("-python", "-py", "-js", "-node", "-dev", "3", "2")


@dataclass(frozen=True)
class Squat:
    target: str
    how: str


class Popular:
    def __init__(self, ecosystem: str, names: list[str]):
        self.ecosystem = ecosystem
        self.ranks: dict[str, int] = {}
        for i, name in enumerate(names, 1):
            self.ranks.setdefault(normalise(ecosystem, name), i)
        ordered = sorted(self.ranks, key=self.ranks.get)
        self.targets = [t for t in ordered[:TARGETS] if len(t) >= MIN_LENGTH]
        self.affix_targets = set(ordered[:AFFIX_TARGETS])
        self.squashed = {}
        self.deletions: dict[str, set[str]] = {}
        for t in self.targets:
            self.squashed.setdefault(_squash(t), t)
            for variant in _deletions(t):
                self.deletions.setdefault(variant, set()).add(t)

    def rank(self, name: str) -> int | None:
        return self.ranks.get(normalise(self.ecosystem, name))

    def squats(self, name: str) -> Squat | None:
        name = normalise(self.ecosystem, name)
        if name in self.ranks or len(name) < MIN_LENGTH:
            return None

        squashed = _squash(name)
        if squashed in self.squashed:
            target = self.squashed[squashed]
            if name.translate(LOOKALIKES) != name and _squash(name, digits=False) != _squash(
                target, digits=False
            ):
                return Squat(target, f"'{target}' with look-alike characters")
            return Squat(target, f"'{target}' without its separators")

        close = set()
        for variant in _deletions(name):
            close |= self.deletions.get(variant, set())
        for target in sorted(close, key=self.ranks.get):
            how = _difference(name, target)
            if how:
                return Squat(target, how)

        for prefix in PREFIXES:
            if name.startswith(prefix) and name[len(prefix):] in self.affix_targets:
                target = name[len(prefix):]
                return Squat(target, f"'{target}' with '{prefix}' in front")
        for suffix in SUFFIXES:
            stem = name[: -len(suffix)]
            if name.endswith(suffix) and stem in self.affix_targets:
                return Squat(stem, f"'{stem}' with '{suffix}' added")
            for target in (f"{stem}-python", f"{stem}-js"):
                if name.endswith(suffix) and target in self.affix_targets:
                    return Squat(target, f"'{target}' with a different ending")
        alt = re.sub(r"^python3-", "python-", name)
        if alt != name and alt in self.ranks:
            return Squat(alt, f"'{alt}' with python3 instead of python")
        return None


@cache
def load_popular(ecosystem: str) -> Popular:
    text = resources.files("pkg_sentry").joinpath(f"data/top-{ecosystem}.txt").read_text("utf-8")
    return Popular(ecosystem, text.split())


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance that counts swapping two neighbours as one edit."""
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        row = [i]
        for j, cb in enumerate(b, 1):
            cost = ca != cb
            value = min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                value = min(value, prev2[j - 2] + 1)
            row.append(value)
        prev2, prev = prev, row
    return prev[-1]


def _squash(name: str, digits: bool = True) -> str:
    name = re.sub(r"[-_.]", "", name)
    return name.translate(LOOKALIKES) if digits else name


def _deletions(name: str) -> set[str]:
    return {name} | {name[:i] + name[i + 1 :] for i in range(len(name))}


def _difference(name: str, target: str) -> str | None:
    if edit_distance(name, target) != 1:
        return None
    if len(name) < len(target):
        return f"'{target}' with a letter missing"
    if len(name) > len(target):
        return f"'{target}' with an extra letter"
    diff = [i for i, (a, b) in enumerate(zip(name, target, strict=True)) if a != b]
    if len(diff) == 2:
        return f"'{target}' with two letters swapped"
    return f"'{target}' with one letter changed"
