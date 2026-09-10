import pytest

from zeebountee.models import Target


def test_target_normalization_standard() -> None:
    target = Target(host="example.com")
    assert target.host == "example.com"


def test_target_normalization_http_scheme() -> None:
    target = Target(host="http://example.com")
    assert target.host == "example.com"


def test_target_normalization_https_scheme() -> None:
    target = Target(host="https://example.com")
    assert target.host == "example.com"


def test_target_normalization_trailing_slash() -> None:
    target = Target(host="https://example.com/")
    assert target.host == "example.com"


def test_target_normalization_full_url() -> None:
    target = Target(host="https://example.com/api/v1/users")
    assert target.host == "example.com"


def test_target_normalization_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid target host provided"):
        Target(host="https://")

    with pytest.raises(ValueError, match="Invalid target host provided"):
        Target(host="")
