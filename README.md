[![Plugin Test](https://github.com/SIOS-Technology-Inc/kong-oidc-jwt-plugin/actions/workflows/test.yaml/badge.svg)](https://github.com/SIOS-Technology-Inc/kong-oidc-jwt-plugin/actions/workflows/test.yaml) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Kong Azure AD JWT Plugin is a [Kong](https://konghq.com/) plugin that verifies access tokens (JWT) from Azure AD and Azure AD B2C.

# Specification
## Enable the plugin on a route

For example, configure this plugin on a route by making the following request:

```bash
$ curl -X POST http://{HOST}:8001/routes/{ROUTE}/plugins \
  -H 'Content-Type: application/json' \
  --data '{
    "name": "oidc-for-azure-ad",
    "config": {
      "upstream_client_id": "e7044a50-e7ce-4859-94a9-5043775b39c0",
      "kong_client_id": "9447719e-ff49-4441-8a7d-092c73af5a06",
      "kong_client_secret": "****",
      "azure_tenant": "tenant_name",
      "header_mapping": {
        "X-Authenticated-Client-Id": { "from": "token", "value": "azp" },
        "X-Authenticated-Client-Name": { "from": "client", "value": "displayName", "encode": "url_encode" },
        "X-Authenticated-User-Id": { "from": "token", "value": "sub" },
        "X-Authenticated-User-Name": { "from": "user", "value": "displayName", "encode": "url_encode" }
      }
    }
  }'
```

## Enable the plugin on a service

For example, configure this plugin on a service by making the following request:

```bash
$ curl -X POST http://{HOST}:8001/services/{SERVICE}/plugins \
  -H 'Content-Type: application/json' \
  --data '{
    "name": "oidc-for-azure-ad",
    "config": {
      "upstream_client_id": "e7044a50-e7ce-4859-94a9-5043775b39c0",
      "kong_client_id": "9447719e-ff49-4441-8a7d-092c73af5a06",
      "kong_client_secret": "****",
      "azure_tenant": "tenant_name",
      "header_mapping": {
        "X-Authenticated-Client-Id": { "from": "token", "value": "azp" },
        "X-Authenticated-Client-Name": { "from": "client", "value": "displayName", "encode": "url_encode" },
        "X-Authenticated-User-Id": { "from": "token", "value": "sub" },
        "X-Authenticated-User-Name": { "from": "user", "value": "displayName", "encode": "url_encode" }
      }
    }
  }'
```

## Parameters

| FORM PARAMETER | REQUIRED | TYPE | DEFAULT | DESCRIPTION |
| -- | -- | -- | -- | -- |
| name | required | string | - | The name of the plugin, in this case `oidc-for-azure-ad` or `oidc-for-azure-ad-b2c`. If you use the Azure AD tenant, select `oidc-for-azure-ad`. If you use Azure the AD B2C tenant, select `oidc-for-azure-ad-b2c`. |
| config.upstream_client_id | required | string | - | The client id of the upstream server that Azure AD generated. |
| config.kong_client_id | required | string | - | The client id of this kong that Azure AD generated. It needs `Application.Read.All` and `User.Read.All` permissions. |
| config.kong_client_secret | required | string | - | The client secret of this kong that Azure AD generated. |
| config.azure_tenant | required | string | - | The name of the Azure tenant that excludes `onmicrosoft.com`.  |
| config.use_kong_auth | optional | boolean | false | Whether this kong use other auth plugins. |
| config.header_mapping | optional | map | (See below) | The definition of headers to the upstream server. See Header Mapping section. |
| config.permit_anonymous | optional | boolean | false | Whether this plugin allows anonymous users. If true, this plugin gives the upstream server the `X-Anonymous` header. The `X-Anonymous` header value is always `true`. |

## Header Mapping

The header mapping is the definition of headers to the upstream server. You can define this using JWT claims (`token`), user resource (`user`), and application resource (`client`).

| FORM PARAMETER | REQUIRED | TYPE | DEFAULT | DESCRIPTION |
| -- | -- | -- | -- | -- |
| from | required | `token` or `user` or `client` | - | The source data of header value. If `token`, it uses JWT claims from the access token. If `user`, it uses authenticated [user's resource](https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0) from Graph API. If `client`, it uses authenticated [application's resource](https://docs.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0) from Graph API. If it doesn't exist, the header is not set. |
| value | required | string | - | The property name of the specified `from` object. If it doesn't exist, the header is not set. |
| encode | optional | `none` or `url_encode` | `none` | The encode type of header value. **If it uses characters that can't be in the HTTP header, it should be `url_encode`**. |

For example, you can define it as below.

```json
{
  "X-Authenticated-Client-Id": { "from": "token", "value": "azp" },
  "X-Authenticated-Client-Name": { "from": "client", "value": "displayName", "encode": "url_encode" },
  "X-Authenticated-User-Id": { "from": "user", "value": "id" },
  "X-Authenticated-User-Name": { "from": "user", "value": "displayName", "encode": "url_encode" }
}
```

The default of both plugins is below.

```json
{
  "X-Authenticated-Client-Id": { "from": "token", "value": "azp" },
  "X-Authenticated-User-Id": { "from": "user", "value": "id" }
}
```

## Usage

Please request with Authorization header that set access token from Azure AD or Azure AD B2C.

```bash
curl -X GET https://localhost:8443/foo/bar \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```
# Docker Image

## Docker Hub

You can pull a kong docker image with this plugin.

For example, pull the docker image:

```bash
$ docker pull 5105tikeda/kong-with-azure-ad-jwt-plugin:latest
```

https://hub.docker.com/r/5105tikeda/kong-with-azure-ad-jwt-plugin

## Build Your Image

If you need to build a docker image yourself, you can use Dockerfile.

For example, build your docker image:

```bash
$ docker build -t kong-with-azure-ad-jwt-plugin:latest .
```

## Run Container

You can start a container just like the official kong container.

https://hub.docker.com/_/kong
