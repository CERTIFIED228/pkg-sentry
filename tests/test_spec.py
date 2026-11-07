import pytest

from pkg_sentry.spec import PackageSpec, SpecError, normalise, parse_spec


@pytest.mark.parametrize(
    "text, expected",
    [
        ("requests", PackageSpec("pypi", "requests")),
        ("requests==2.31.0", PackageSpec("pypi", "requests", "2.31.0")),
        ("pypi:Django==5.0", PackageSpec("pypi", "Django", "5.0")),
        ("  requests == 2.31.0 ", PackageSpec("pypi", "requests", "2.31.0")),
        ("npm:lodash", PackageSpec("npm", "lodash")),
        ("npm:lodash@4.17.21", PackageSpec("npm", "lodash", "4.17.21")),
        ("npm:@babel/core@7.24.0", PackageSpec("npm", "@babel/core", "7.24.0")),
        ("@babel/core", PackageSpec("npm", "@babel/core")),
        ("@types/node@20.1.0", PackageSpec("npm", "@types/node", "20.1.0")),
    ],
)
def test_parse(text, expected):
    assert parse_spec(text) == expected


def test_default_ecosystem_can_be_npm():
    assert parse_spec("express@4.19.2", default="npm") == PackageSpec("npm", "express", "4.19.2")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "requests>=2",  # only exact pins make sense for checking one release
        "npm:",
        "npm:@babel",
        "npm:@/core",
        "npm:../../etc/passwd",
        "-requests",
        "requests==",
        "cargo:serde",
        "npm:lodash@",
        "npm:" + "a" * 215,
    ],
)
def test_rejects_bad_specs(text):
    with pytest.raises(SpecError):
        parse_spec(text)


def test_label():
    assert parse_spec("npm:lodash@4.17.21").label == "lodash@4.17.21 (npm)"
    assert parse_spec("requests").label == "requests (PyPI)"


@pytest.mark.parametrize(
    "ecosystem, name, expected",
    [
        ("pypi", "Python_Dateutil", "python-dateutil"),
        ("pypi", "zope.interface", "zope-interface"),
        ("pypi", "a--b__c", "a-b-c"),
        ("npm", "Lodash", "lodash"),
        ("npm", "@Babel/Core", "@babel/core"),
    ],
)
def test_normalise(ecosystem, name, expected):
    assert normalise(ecosystem, name) == expected
