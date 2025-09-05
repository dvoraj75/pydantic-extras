from typing import Iterable, Self, Any
from urllib.parse import urlsplit, unquote, quote, parse_qsl, urlunsplit, urlencode

from pydantic import GetJsonSchemaHandler
from pydantic_core import Url, core_schema


_DEFAULT_SENSITIVE_KEYS = {
    "token",
    "access_token",
    "auth",
    "apikey",
    "api_key",
    "password",
    "pass",
    "secret",
    "key",
}


class SecretURL(str):
    """
    A string-like URL type that:
      - validates input as a proper URL,
      - masks the password in userinfo and sensitive query parameters
        when converted to str()/repr()/JSON,
      - allows retrieving the full unmasked value via .unmasked().

    Note: Mainly intended for DSN/URI values containing credentials
    (e.g. PostgreSQL, AMQP, Redis, ...).
    """

    __slots__ = ("__unmasked", "__masked")

    def __new__(
        cls,
        value: str,
        *,
        sensitive_keys: Iterable[str] | None = None,
        mask_token: str = "***",
    ) -> Self:
        Url(value)
        obj = str.__new__(cls, value)
        obj.__unmasked = value
        obj.__masked = _mask_url(
            value,
            sensitive_keys={k for k in (sensitive_keys or _DEFAULT_SENSITIVE_KEYS)},
            mask_token=mask_token
        )
        return obj

    @property
    def masked(self) -> str:
        """The masked URL string."""
        return self.__masked

    @property
    def unmasked(self) -> str:
        return self.__unmasked

    def __str__(self) -> str:
        return self.masked

    def __repr__(self) -> str:
        return f"SecretURL({self.masked!r})"

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source: Any, _handler: Any
    ) -> core_schema.CoreSchema:
        def validate(v: Any) -> "SecretURL":
            if isinstance(v, SecretURL):
                return v
            if not isinstance(v, str):
                raise TypeError("SecretURL expects a string URL")
            return cls(v)

        # if context={"secret_url_unmasked": True} -> return full unmasked URL
        def serialize(v: "SecretURL", _info: core_schema.SerializationInfo):
            if isinstance(_info.context, dict) and _info.context.get(
                "secret_url_unmasked"
            ):
                return v.unmasked
            return v.masked

        return core_schema.no_info_after_validator_function(
            validate,
            core_schema.url_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                serialize, when_used="always", info_arg=True
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _core_schema: core_schema.CoreSchema,
        _handler: GetJsonSchemaHandler,
    ) -> dict[str, Any]:
        return {"type": "string", "format": "uri", "x-masked": True}


def _mask_url(url: str, *, sensitive_keys: set[str], mask_token: str) -> str:
    _url = urlsplit(url)
    netloc = _url.netloc

    if "@" in netloc:
        userinfo, hostpart = _url.netloc.rsplit("@", 1)
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
            userinfo_masked = f"{quote(unquote(username))}:{mask_token}"
        else:
            userinfo_masked = userinfo

        netloc = f"{userinfo_masked}@{hostpart}"

    q_params = [(k, mask_token if k.lower() in sensitive_keys else v) for k, v in parse_qsl(_url.query, keep_blank_values=True)]
    return urlunsplit((_url.scheme, netloc, _url.path, urlencode(q_params), _url.fragment))