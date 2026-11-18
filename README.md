# nfwpunch

**nfwpunch** is a dynamic firewall hole punching daemon for nftables.

It works as an intermediary between Nginx as the authentication gateway and nftables as the network access enforcement layer.

The service runs as a daemon, listening for requests on a UNIX socket.

A typical scenario involves the following setup:

1. A user-configured service hidden behind a firewall.
2. A web server or reverse proxy to conduct user authentication and authorization.
3. Dynamic firewall hole puncher (this service).

Once the web server conducts user authentication and authorization, it sends a request to this daemon to grant temporary access thru the firewall to the configured service ports for client IP address.

## Security considerations

While this service allows restricting access to clients from authorized IP addresses, carefully review the following.

**IP-based authorization is not user-based authorization**. If two people share a NAT address, both can use the authorized ports once that address is in the firewall set. If this is unacceptable, consider a VPN with per-user credentials, or a layer-4 proxy that authenticates individual connections.

**Forged client IP** may allow access for attackers. Trust only known reverse proxies.

## Compilation

To compile the program yourself install the required dependencies:

* dpkg (for the DEB package)
* gcc
* git
* libc6-dev
* make
* realpath
* scdoc (for the manual page)
* sed

To build the program: `make nfwpunchd`.

To build the manual page: `make doc`.

To build DEB package: `make deb`.

To build everything: `make` or `make all`.

## Installation

For Debian-based Linux distributions (Debian, Ubuntu, etc) the recommended installation method is using the DEB package.
Download a package corresponding to the CPU architecture of your system from **Releases** page, or build the package yourself: `make deb`.
Install the package with `apt` (replace the file name with the actual downloaded file name): `sudo apt install ./downloaded_deb_file.deb`.

For non-Debian Linux distributions the installation can be done with `sudo make install` command.
Ensure that the program and (optionally) documentation were compiled with `make nfwpunchd` and `make doc` prior to the installation.

Once the program is installed, a new `systemd` service is added (the service is disabled by default): `nfwpunch.service`.

## Usage

Refer to [the manual page](doc/nfwpunch.8.scd) for the configuration options and working modes of the program.

Example Nginx configurations are available in the `examples` directory.
Either variant may be used:

* Lua variant: [examples/nginx-lua/nfwpunchd-nginx.conf](examples/nginx-lua/nfwpunchd-nginx.conf)
* Perl variant: [examples/nginx-perl/nfwpunchd-nginx.conf](examples/nginx-perl/nfwpunchd-nginx.conf) and [examples/nginx-perl/nfwpunchd-nginx.pl](examples/nginx-perl/nfwpunchd-nginx.pl)

## Authors

**nfwpunch** is written by Aleksei Ilin.

## Copyright

Copyright © 2026 Aleksei Ilin

**nfwpunch** can be used, and/or redistributed, and/or modified under the terms specified within the included license.

A copy of the license is included within the source code: [LICENSE](LICENSE).

## AI Disclosure

This project utilizes AI-assisted programming tools (specifically GitHub Copilot) for code generation, boilerplate scaffolding, and documentation.
