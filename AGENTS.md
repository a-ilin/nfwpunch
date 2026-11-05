# Dynamic firewall hole punching daemon to use with Nginx or Apache

A good way to implement this is to treat Nginx as the authentication gateway and nftables as the network access enforcement layer.

The key requirement is that Nginx runs as a restricted user, while nftables changes require root privileges. You should not give Nginx unrestricted access to the firewall.

Instead, use a small, privileged helper that accepts narrowly defined requests from Nginx and manages temporary firewall permissions.

## Project layout

The project layout is as follows:

project
 |-bin      : Generated files and built artifacts
 |-debian   : Debian-related configuration
 |-dist     : Files for the distribution
 |-doc      : Documentation for distribution
 |-examples : Example configuration, not for distribution

## Building

The project can be built as independent executable, or a Debian package.
Either way is done using `make` tool.
All generated files during the build are contained in `bin` directory.

To build the program only, call `make nfwpunchd`.
To build the documentation, call `make doc`.
To build the Debian package, call `make deb`.
To clean the `bin` directory, call `make clean`.

## Architecture

Nginx (unprivileged)
    |
    | Unix socket: /run/nfwpunch/nfwpunch.sock
    | JSON-like line protocol
    v
nfwpunchd (root)
    |
    | Validates IP, service, timeout
    | Maps service to fixed ports
    | Executes fixed nft commands
    v
nftables

## Security properties

- Unix socket restricted to a dedicated group.
- No shell execution by Nginx.
- Only predefined services and ports from the config file.
- IPv4 and IPv6 validation using inet_pton().
- Maximum authorization lifetime.
- nftables commands constructed from validated values.
- One request per connection.
- Explicit authorize and revoke operations.
- Root privileges confined to the daemon.
The implementation below uses a simple line-based protocol rather than a full JSON parser. This keeps the daemon small and avoids adding a JSON library dependency.

## Example API calls

Requests:
authorize 203.0.113.10 web 1800
revoke 203.0.113.10 web

Responses:
OK authorized
OK revoked
ERROR invalid_request
