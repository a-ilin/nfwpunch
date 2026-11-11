nfwpunch(8)


# NAME

*nfwpunch* - firewall hole punching daemon for nftables.


# SYNOPSIS

*nfwpunchd*


# DESCRIPTION

*nfwpunch* is a dynamic firewall hole punching daemon for nftables.

It runs as a daemon, listening for requests on a UNIX socket.
Typically, a web server is configured to conduct user authentication and authorization,
following the request to grant temporary access thru the firewall to the configured service ports.


# CONFIGURATION

The configuration consists of 2 parts:
. nfwpunchd configuration: _/etc/nfwpunch.conf_.
. Web server configuration: Nginx example is available at _/usr/share/doc/nfwpunch/nfwpunchd-nginx.conf_.

## /etc/nfwpunch.conf

_/etc/nfwpunch.conf_ contains the configuration for this daemon. It specifies service names with matching
protocols (TCP/UDP) and ports.

Refer to the installed configuration file for available options.

## Web server configuration

The provided example is for Nginx server: _/usr/share/doc/nfwpunch/nfwpunchd-nginx.conf_.

Other web servers can be used as well with this service, assuming the UNIX socket protocol is followed.

The web server should be configured to write to the UNIX socket upon successful user authentication.


# UNIX socket protocol

This service opens UNIX socket at: _/run/nfwpunch/nfwpunch.sock_.

## Access authorization

In order to *authorize* access, the web server has to write to the socket:++
_authorize CLIENT_IP SERVICE_NAME TIMEOUT_SECONDS_

where:
. _CLIENT_IP_ is the IP address of the client.
. _SERVICE_NAME_ is the corresponding service name configured in _/etc/nfwpunch.conf_.
. _TIMEOUT_SECONDS_ is the timeout for the firewall to keep ports open.

In case of successful firewall change, the service replies:++
_OK authorized_.

## Access revoke

In order to *close* access, the web server has to write to the socket:++
_revoke CLIENT_IP SERVICE_NAME_

where:
. _CLIENT_IP_ is the IP address of the client.
. _SERVICE_NAME_ is the corresponding service name configured in _/etc/nfwpunch.conf_.

In case of successful firewall change, the service replies:++
_OK revoked_.

Note that typically access revoke is not necessary, since it will be automatically revoked
after the timeout specified during authorization.


# Firewall mode

No explicit firewall configuration is required: this service creates necessary chains and rules upon launch.

However, for the entire setup to make sense, the firewall must be configured to drop network packets by default.

This service does not enforce packets drop in the firewall by default to avoid unexpected access disruptions.


# AUTHORS

*nfwpunch* is written by Aleksei Ilin.


# COPYRIGHT

Copyright © 2026 Aleksei Ilin

*nfwpunch* can be used, and/or redistributed, and/or modified under the terms specified within the included license file.
