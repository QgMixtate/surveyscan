import pytest

from surveyscan.versions import (dpkg_cmp, generic_cmp, numeric_tuple_cmp, parse_bdu_versions, rpm_cmp,
                                 upstream_of, version_in)


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0),
    ("1:1.0", "2.0", 1),                      # эпоха
    ("1.0~rc1", "1.0", -1),                   # ~ раньше релиза
    ("9.3p2", "9.3p1", 1),
    ("9.3", "9.3p1", -1),
    ("1.2.10-1", "1.2.9-1", 1),
    ("2.31-13+deb11u5", "2.31-13+deb11u4", 1),
])
def test_dpkg(a, b, expected):
    assert dpkg_cmp(a, b) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.3-1.el8", "1.2.10-1.el8", -1),
    ("1.0~rc1", "1.0", -1),
    ("1.0^git1", "1.0", 1),
    ("2:1.0-1", "1:9.0-1", 1),
    ("1.0a", "1.0", 1),
])
def test_rpm(a, b, expected):
    assert rpm_cmp(a, b) == expected


@pytest.mark.parametrize("version,eco,expected", [
    ("1:8.4p1-5+deb11u3+ci202312171324+astra2", "deb", "8.4p1"),
    ("1.9.15p5-3ubuntu5.24.04.4", "deb", "1.9.15p5"),
    ("1.1.1n-0+deb11u5", "deb", "1.1.1n"),
    ("1:3.0.13-1.el7.3", "rpm", "3.0.13"),
    ("5.15.0-70-generic", "kernel", "5.15.0"),
    ("8.9p1 Ubuntu 3ubuntu0.10", "svc", "8.9p1"),
])
def test_upstream(version, eco, expected):
    assert upstream_of(version, eco) == expected


@pytest.mark.parametrize("text,inside,outside", [
    ("от 2.0 до 2.4.54 включительно", ["2.0", "2.4.54", "2.3"], ["1.9", "2.4.55"]),
    ("от 2.0 до 2.4.54", ["2.4.53"], ["2.4.54"]),
    ("до 9.3p2", ["9.3p1", "8.4p1"], ["9.3p2", "9.4"]),
    ("до 8.9p1 (включительно)", ["8.9p1"], ["9.0"]),
    ("1.18.0 и ранее", ["1.18.0", "1.16.1"], ["1.18.1"]),
    ("4.0, 4.1", ["4.0", "4.1"], ["4.2"]),
    ("до 13.14, от 14.0 до 14.11", ["13.11", "14.5"], ["13.14", "14.11", "15.0"]),
    ("версии до 1.9.12p1 включительно", ["1.9.12p1", "1.9.5p2"], ["1.9.12p2"]),
    ("от 1.0", ["1.0", "7.5"], ["0.9"]),
    ("1.0 – 2.0", ["1.5", "2.0"], ["2.1"]),
    ("все версии", ["0.1", "99"], []),
])
def test_bdu_ranges(text, inside, outside):
    parsed = parse_bdu_versions(text)
    assert parsed, text
    for v in inside:
        assert version_in(v, parsed), f"{v} должна входить в «{text}»"
    for v in outside:
        assert not version_in(v, parsed), f"{v} не должна входить в «{text}»"


@pytest.mark.parametrize("text", ["-", "", None, "Astra Linux SE 1.7", "ветки 3.0 до выхода исправления 3.0.14"])
def test_bdu_unparsed(text):
    assert parse_bdu_versions(text) is None


def test_package_revision_not_mistaken_for_range():
    # «2.4.54-1» — это версия с ревизией, а не диапазон 2.4.54…1
    parsed = parse_bdu_versions("2.4.54-1")
    assert parsed and parsed[0].exact == "2.4.54-1"


def test_windows_build():
    assert numeric_tuple_cmp("10.0.19045.4291", "10.0.19045.5011") == -1
    assert numeric_tuple_cmp("10.0.19045.5011", "10.0.19045.5011") == 0
    assert generic_cmp("v1.2", "1.2") == 0
