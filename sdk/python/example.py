from ezoidc.api.v1.client import EzoidcClient
import os
import functools


@functools.cache
async def token_provider():
    return os.environ.get("EZOIDC_TOKEN")


async def main():
    host = os.environ.get("EZOIDC_HOST", "https://test.ezoidc.dev")
    client = EzoidcClient(base_url=host, token=token_provider)

    # fetch server metadata
    print(await client.metadata())

    # fetch variables
    result = await client.variables()
    for v in result.variables:
        print(f"{v.name}={v.string} (export={v.export}, redact={v.redact})")

    # update environment with exportable variables
    os.environ.update(result.environ())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
