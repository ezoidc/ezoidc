"""ezoidc v1.0 API client."""

from collections.abc import Awaitable, Callable
from typing import cast

import aiohttp
from pydantic import BaseModel, Field

from .models import (
    ErrorResponse,
    MetadataResponse,
    VariablesRequest,
    VariablesResponse,
)

TokenProvider = str | Callable[[], str | Awaitable[str]]


class APIError(Exception):
    def __init__(self, status: int, error: str, reason: str = ""):
        self.status = status
        self.error = error
        self.reason = reason
        super().__init__(f"{reason}: {error} (status {status})")


class EzoidcClient(BaseModel):
    """
    API client to interact with an ezoidc-server using aiohttp.
    """

    base_url: str
    token: TokenProvider
    headers: dict[str, str] = Field(default_factory=dict)

    async def metadata(self) -> MetadataResponse:
        """
        Retrieve metadata from the ezoidc server.
        https://docs.ezoidc.dev/server/api/#ezoidc
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/ezoidc",
                headers=self.headers,
            ) as resp:
                await self._raise_for_error(resp)
                return MetadataResponse.model_validate(await resp.json())

    async def variables(
        self,
        request: VariablesRequest | None = None,
    ) -> VariablesResponse:
        """
        Retrieve variables from the ezoidc server.
        https://docs.ezoidc.dev/server/api/#ezoidc10variables
        """
        req = request or VariablesRequest()
        token = await self._resolve_token()
        headers = {
            **self.headers,
            "Authorization": f"Bearer {token}",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/ezoidc/1.0/variables",
                headers=headers,
                json=req.model_dump(),
            ) as resp:
                await self._raise_for_error(resp)
                return VariablesResponse.model_validate(await resp.json())

    async def _resolve_token(self) -> str:
        if isinstance(self.token, str):
            return self.token
        result = self.token()
        if isinstance(result, Awaitable):
            return cast(str, await result)
        return result

    async def _raise_for_error(self, resp: aiohttp.ClientResponse) -> None:
        if resp.status >= 500:
            raise APIError(
                resp.status, "Server error", "An error occurred on the server"
            )

        if resp.status >= 400:
            body = await resp.json()
            err = ErrorResponse.model_validate(body)
            raise APIError(resp.status, err.error, err.reason)
