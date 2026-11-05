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
* nfwpunchd configuration: /etc/nfwpunch.conf
* web server configuration: nginx example is available at /usr/share/doc/nfwpunch/nfwpunchd-nginx.conf


# AUTHORS

*nfwpunch* is written by Aleksei Ilin.


# COPYRIGHT

Copyright © 2026 Aleksei Ilin

*nfwpunch* can be used, and/or redistributed, and/or modified under the terms specified within the included license file.
