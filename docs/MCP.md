# Authenticated data access through Tether

The [MCP package](../packages/mcp/README.md) connects model clients to account-authorized service data through existing Tether forwarding. It adds application authorization above the transport; saved device trust is not proof of a user's account.

The embedding host configures an access-token verifier, a current grant provider, and fixed service adapters. The bundled PageIndex adapter exposes bounded document listing, document reads and search. Resource reads use the same authorization checks as tools. No admin or write endpoint is exposed.

Build and onboarding details, policy semantics, API contracts and measured limits are in the package guide. No new relay, account provider or public endpoint is created by building the package. The account-framework UI and the live sign-in provider remain separate work.
