import pytest

from pkg_sentry.names import Popular, edit_distance, load_popular

TOP_PYPI = ["requests", "numpy", "colorama", "python-dateutil", "urllib3", "jellyfish",
            "beautifulsoup4", "django", "boto3", "pyyaml", "six", "request"]
TOP_NPM = ["lodash", "cross-env", "express", "react", "@babel/core", "chalk", "electron",
           "discord.js", "@typescript-eslint/parser"]


@pytest.fixture
def pypi():
    return Popular("pypi", TOP_PYPI)


@pytest.fixture
def npm():
    return Popular("npm", TOP_NPM)


@pytest.mark.parametrize(
    "name, target",
    [
        ("reqeusts", "requests"),       # swapped letters
        ("requets", "requests"),        # missing letter
        ("colourama", "colorama"),      # extra letter
        ("nunpy", "numpy"),             # wrong letter
        ("jeIlyfish", "jellyfish"),     # capital I for l
        ("urlib3", "urllib3"),
        ("pythondateutil", "python-dateutil"),  # separators dropped
        ("python3-dateutil", "python-dateutil"),
        ("djang0", "django"),           # digit for letter
        ("beautifulsoup", "beautifulsoup4"),
    ],
)
def test_pypi_typosquats(pypi, name, target):
    match = pypi.squats(name)
    assert match is not None and match.target == target


@pytest.mark.parametrize(
    "name, target",
    [
        ("crossenv", "cross-env"),      # the classic 2017 npm attack
        ("lodahs", "lodash"),
        ("expres", "express"),
        ("@babel/croe", "@babel/core"),
        ("discordjs", "discord.js"),
        ("electorn", "electron"),
        ("@typescript_eslint/parser", "@typescript-eslint/parser"),
    ],
)
def test_npm_typosquats(npm, name, target):
    match = npm.squats(name)
    assert match is not None and match.target == target


@pytest.mark.parametrize(
    "name",
    [
        "requests",          # the real one
        "Requests",          # same after normalising
        "python_dateutil",   # PyPI treats - _ . as the same
        "request",           # popular in its own right
        "pandas",            # nothing like anything
        "six",               # short names are too crowded to judge
        "sax",
        "boto",              # 4 letters, too short to call
    ],
)
def test_not_typosquats(pypi, name):
    assert pypi.squats(name) is None


def test_popular_names_are_never_squats(npm):
    assert npm.squats("react") is None
    assert npm.squats("Lodash") is None


def test_rank_is_kept(pypi):
    assert pypi.rank("requests") == 1
    assert pypi.rank("REQUESTS") == 1
    assert pypi.rank("nothing-like-it") is None


def test_explains_the_trick(pypi, npm):
    assert "swapped" in pypi.squats("reqeusts").how
    assert "without" in npm.squats("crossenv").how


def test_bundled_lists_load():
    top = load_popular("pypi")
    assert top.rank("requests") is not None
    assert load_popular("npm").rank("lodash") is not None
    assert load_popular("pypi") is top  # cached


@pytest.mark.parametrize(
    "a, b, d",
    [("abc", "abc", 0), ("abc", "acb", 1), ("abc", "ab", 1), ("abc", "abd", 1),
     ("abc", "xyz", 3), ("", "ab", 2), ("ca", "abc", 3)],
)
def test_edit_distance(a, b, d):
    assert edit_distance(a, b) == d
