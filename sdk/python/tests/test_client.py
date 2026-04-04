import unittest
from unittest.mock import AsyncMock, patch

import aiohttp

from ezoidc.api.v1.client import APIError, EzoidcClient
from ezoidc.api.v1.models import VariablesRequest


BASE_URL = "http://localhost"
API_VERSION = "1.0"


def mock_response(status=200, json_data=None):
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data or {})
    ctx = AsyncMock()
    ctx.__aenter__.return_value = resp
    return ctx


class TestMetadata(unittest.IsolatedAsyncioTestCase):
    @patch("aiohttp.ClientSession.get")
    async def test_metadata(self, mock_get):
        mock_get.return_value = mock_response(
            json_data={"ezoidc": True, "api_version": API_VERSION}
        )

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        result = await client.metadata()

        self.assertTrue(result.ezoidc)
        self.assertEqual(result.api_version, API_VERSION)

    @patch("aiohttp.ClientSession.get")
    async def test_metadata_server_error(self, mock_get):
        mock_get.return_value = mock_response(status=500)

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        with self.assertRaises(APIError) as ctx:
            await client.metadata()

        self.assertEqual(ctx.exception.status, 500)

    @patch("aiohttp.ClientSession.get")
    async def test_metadata_with_custom_headers(self, mock_get):
        mock_get.return_value = mock_response(
            json_data={"ezoidc": True, "api_version": API_VERSION}
        )

        client = EzoidcClient(
            base_url=BASE_URL, token="tok", headers={"X-Custom": "val"}
        )
        await client.metadata()

        call_kwargs = mock_get.call_args
        self.assertEqual(call_kwargs.kwargs["headers"]["X-Custom"], "val")

    @patch("aiohttp.ClientSession.get")
    async def test_metadata_client_error(self, mock_get):
        mock_get.return_value = mock_response(
            status=400, json_data={"error": "bad request", "reason": "invalid"}
        )

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        with self.assertRaises(APIError) as ctx:
            await client.metadata()

        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.error, "bad request")
        self.assertEqual(ctx.exception.reason, "invalid")


class TestVariables(unittest.IsolatedAsyncioTestCase):
    @patch("aiohttp.ClientSession.post")
    async def test_variables(self, mock_post):
        mock_post.return_value = mock_response(
            json_data={
                "variables": [
                    {
                        "name": "FOO",
                        "value": {"string": "bar"},
                        "export": "FOO",
                        "redact": False,
                    },
                    {
                        "name": "SECRET",
                        "value": {"string": "s3cret"},
                        "export": "SECRET",
                        "redact": True,
                    },
                ]
            }
        )

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        variables = (await client.variables()).variables

        self.assertEqual(len(variables), 2)
        self.assertEqual(variables[0].name, "FOO")
        self.assertEqual(variables[0].string, "bar")
        self.assertFalse(variables[0].redact)
        self.assertEqual(variables[1].name, "SECRET")
        self.assertTrue(variables[1].redact)

    @patch("aiohttp.ClientSession.post")
    async def test_variables_empty(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        variables = (await client.variables()).variables

        self.assertEqual(len(variables), 0)

    @patch("aiohttp.ClientSession.post")
    async def test_variables_with_params(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        await client.variables(VariablesRequest(params={"env": "prod"}))

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        self.assertEqual(call_kwargs.kwargs["json"], {"params": {"env": "prod"}})

    @patch("aiohttp.ClientSession.post")
    async def test_variables_sends_auth_header(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        client = EzoidcClient(base_url=BASE_URL, token="my-token")
        await client.variables()

        call_kwargs = mock_post.call_args
        self.assertEqual(
            call_kwargs.kwargs["headers"]["Authorization"], "Bearer my-token"
        )

    @patch("aiohttp.ClientSession.post")
    async def test_variables_with_custom_headers(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        client = EzoidcClient(
            base_url=BASE_URL, token="tok", headers={"X-Custom": "val"}
        )
        await client.variables()

        call_kwargs = mock_post.call_args
        self.assertEqual(call_kwargs.kwargs["headers"]["X-Custom"], "val")

    @patch("aiohttp.ClientSession.post")
    async def test_variables_server_error(self, mock_post):
        mock_post.return_value = mock_response(status=502)

        client = EzoidcClient(base_url=BASE_URL, token="tok")
        with self.assertRaises(APIError) as ctx:
            await client.variables()

        self.assertEqual(ctx.exception.status, 502)


class TestTokenProvider(unittest.IsolatedAsyncioTestCase):
    @patch("aiohttp.ClientSession.post")
    async def test_string_token(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        client = EzoidcClient(base_url=BASE_URL, token="static-token")
        await client.variables()

        call_kwargs = mock_post.call_args
        self.assertEqual(
            call_kwargs.kwargs["headers"]["Authorization"], "Bearer static-token"
        )

    @patch("aiohttp.ClientSession.post")
    async def test_callable_token(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        client = EzoidcClient(base_url=BASE_URL, token=lambda: "dynamic-token")
        await client.variables()

        call_kwargs = mock_post.call_args
        self.assertEqual(
            call_kwargs.kwargs["headers"]["Authorization"], "Bearer dynamic-token"
        )

    @patch("aiohttp.ClientSession.post")
    async def test_async_callable_token(self, mock_post):
        mock_post.return_value = mock_response(json_data={"variables": []})

        async def async_token():
            return "async-token"

        client = EzoidcClient(base_url=BASE_URL, token=async_token)
        await client.variables()

        call_kwargs = mock_post.call_args
        self.assertEqual(
            call_kwargs.kwargs["headers"]["Authorization"], "Bearer async-token"
        )


class TestAPIError(unittest.TestCase):
    def test_error_message(self):
        err = APIError(401, "unauthorized", "token expired")
        self.assertIn("401", str(err))
        self.assertIn("unauthorized", str(err))
        self.assertIn("token expired", str(err))

    def test_error_attributes(self):
        err = APIError(403, "forbidden", "access denied")
        self.assertEqual(err.status, 403)
        self.assertEqual(err.error, "forbidden")
        self.assertEqual(err.reason, "access denied")


class TestInvalidBaseURL(unittest.IsolatedAsyncioTestCase):
    async def test_metadata_invalid_base_url(self):
        client = EzoidcClient(base_url="not a url", token="tok")
        with self.assertRaises(aiohttp.InvalidUrlClientError):
            await client.metadata()


if __name__ == "__main__":
    unittest.main()
