# Aeitron API

Welcome to the Aeitron official main API repository.

This API is currently in public v1 release and provides programmatic control over Aeitron's global edge network, cloud infrastructure, and workload placement services.

We appreciate your feedback and contributions to help us improve.

## Overview

The Aeitron API allows you to interact with Aeitron's services programmatically. You can manage your Aeitron cloud resources, edge routing, DNS, security policies, compute instances, storage, and billing through this API.

The complete OpenAPI 3.1.0 specification is available in [`openapi.yaml`](openapi.yaml).

## Getting Started

To get started with the Aeitron API, follow these steps:

1. Sign up for an [Aeitron account](https://aeitron.com/).
2. Obtain your API token from the [Aeitron dashboard](https://app.aeitron.com/settings/api-keys).
3. Refer to the [Aeitron API documentation](https://api.aeitron.com/docs) for usage instructions and interactive playgrounds ([Scalar](https://api.aeitron.com/docs) / [ReDoc](https://api.aeitron.com/redoc)).

### Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/aeitron/api.git
cd api

# Start with Docker Compose
docker compose up -d
```

### Local Development

```bash
# Run tests
go test -v ./...

# Start gateway locally on port 8000
go run ./cmd/api-gateway
```

## SDKs & Tools

To help you get started with the Aeitron API, we provide SDKs and tools in various programming languages. The usage & documentation for each SDK can be found in the respective repositories:

* **TypeScript** - https://github.com/aeitron/api-typescript-sdk
* **Python** - https://github.com/aeitron/api-python-sdk
* **Go** - https://github.com/aeitron/api-go-sdk
* **Terraform** - https://github.com/aeitron/terraform-provider-aeitron
* **CLI** - https://github.com/aeitron/cli
* **MCP Server** - https://github.com/aeitron/mcp-server
* **Postman Collection** - https://www.postman.com/aeitron-api

## Architecture

For in-depth architectural and technical specifications of the gateway (sub-5ms edge caching, HMAC/JWT validation, lock-striped rate limiting, Stripe-grade idempotency, and real-time SSE streaming), please refer to [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Change log

For information on the latest changes to the API, please refer to the [change log](CHANGELOG.md).

## Issues

If you encounter any issues or have any questions, please check our [issues page](https://github.com/aeitron/api/issues) to see if it has already been reported. If not, feel free to open a new issue.

## Discussions

Join the conversation and share your thoughts on the Aeitron API in our [discussions page](https://github.com/aeitron/api/discussions).

## License

This project is licensed under the [MIT License](LICENSE).
