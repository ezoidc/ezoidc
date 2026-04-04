# ezoidc

Python SDK for [ezoidc](https://github.com/ezoidc/ezoidc).

## Install

```
uv add ezoidc
```

## Usage

```python
import os
from ezoidc.api.v1.client import EzoidcClient

client = EzoidcClient(base_url="http://localhost:8080", token="your-token")

result = await client.variables()
for var in result.variables:
    print(var.name, var.string)

os.environ.update(result.environ())
```
