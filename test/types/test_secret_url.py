import pytest

from pydantic import BaseModel

from pydantic_extras.types import SecretURL


class TestModel(BaseModel):
    url: SecretURL


@pytest.mark.parametrize(
    "raw,masked",
    [
        (
            "postgresql://u:p@localhost:5432/db?token=abc",
            "postgresql://u:***@localhost:5432/db?token=%2A%2A%2A",
        ),
        (
            "https://api.example.com/data?apikey=abc123&user=john",
            "https://api.example.com/data?apikey=%2A%2A%2A&user=john",
        ),
        (
            "amqp://user@mq.example.com/vhost",
            "amqp://user@mq.example.com/vhost",
        ),
        (
            "redis://user:secret@[::1]:6379/0",
            "redis://user:***@[::1]:6379/0",
        ),
        (
            "postgresql://us%3Aer:p%40ss@db.example.com/app",
            "postgresql://us%3Aer:***@db.example.com/app",
        ),
        (
            "https://svc.com/cb?access_token=A&secret=B&key=C&other=ok",
            "https://svc.com/cb?access_token=%2A%2A%2A&secret=%2A%2A%2A&key=%2A%2A%2A&other=ok",
        ),
        (
            "https://x.com/?token=&q=foo",
            "https://x.com/?token=%2A%2A%2A&q=foo",
        ),
        (
            "https://x.com/?token=one&token=two",
            "https://x.com/?token=%2A%2A%2A&token=%2A%2A%2A",
        ),
        (
            "https://host/path#section?apikey=abc",
            "https://host/path#section?apikey=abc",
        ),
        (
            "scheme://user:p%40ss:word@host/path?password=abc",
            "scheme://user:***@host/path?password=%2A%2A%2A",
        ),
    ],
)
def test_masking_secret_url(raw: str, masked: str) -> None:
    url = SecretURL(raw)
    assert url.unmasked == raw
    assert url == raw
    assert str(url) == masked
    assert repr(url) == f"SecretURL({masked!r})"


def test_sensitive_keys_case_insensitive() -> None:
    raw = "https://ex.com/?Api_Key=XYZ&AUTH=1&Pass=2"
    masked = "https://ex.com/?Api_Key=%2A%2A%2A&AUTH=%2A%2A%2A&Pass=%2A%2A%2A"
    assert str(SecretURL(raw)) == masked


def test_custom_sensitive_keys_and_token() -> None:
    url = SecretURL(
        "https://x.com/?sessionid=abc&user=jan",
        sensitive_keys={"sessionid"},
        mask_token="(redacted)",
    )
    assert str(url) == "https://x.com/?sessionid=%28redacted%29&user=jan"


def test_pydantic_dump_masked_by_default() -> None:
    dumped = TestModel(url="postgresql://u:p@h/db?token=a").model_dump()
    assert dumped["url"] == "postgresql://u:***@h/db?token=%2A%2A%2A"


def test_pydantic_dump_unmasked_with_context() -> None:
    dumped = TestModel(url="postgresql://u:p@h/db?token=a").model_dump(
        context={"secret_url_unmasked": True}
    )
    assert dumped["url"] == "postgresql://u:p@h/db?token=a"


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-url",
        "http//missing-colon.com",
        "://no-scheme.com",
    ],
)
def test_invalid_url_raises(bad: str) -> None:
    with pytest.raises(ValueError):
        SecretURL(bad)


def test_string_behaviour() -> None:
    raw = "https://ex.com/?token=abc"
    url = SecretURL(raw)
    assert url == raw
    assert url.startswith("https://ex.com/")
    assert str(url).endswith("token=%2A%2A%2A")
    d = {url: "ok"}
    assert d[raw] == "ok"
