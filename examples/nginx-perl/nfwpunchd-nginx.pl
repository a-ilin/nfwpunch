package NFWPunch::Nginx;

use strict;
use warnings;

use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

my $SOCKET_PATH = "/run/nfwpunch/nfwpunch.sock";
my $SOCKET_TIMEOUT = 1;

sub _request_nfwpunch {
    my ($r, $request) = @_;

    my $sock = IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $SOCKET_PATH,
        Timeout => $SOCKET_TIMEOUT,
    );

    if (!$sock) {
        $r->log_error("nfwpunchd connect failed: $!");
        return;
    }

    if (!print {$sock} $request) {
        $r->log_error("nfwpunchd write failed: $!");
        close $sock;
        return;
    }

    my $reply = <$sock>;

    if (!close $sock) {
        $r->log_error("nfwpunchd close failed: $!");
    }

    if (!defined($reply)) {
        $r->log_error("nfwpunchd read failed");
        return;
    }

    $reply =~ s/[\r\n]+\z//;

    return $reply;
}

sub authorize_web {
    my ($r) = @_;

    my $ip = $r->variable("remote_addr");
    my $reply = _request_nfwpunch($r, "authorize $ip web 1800\n");

    return 502 if !defined($reply);

    if ($reply ne "OK authorized") {
        $r->log_error("nfwpunchd replied: $reply");
        return 403;
    }

    $r->send_http_header("text/html");
    $r->print("Access granted\n");

    return 200;
}

sub revoke_web {
    my ($r) = @_;

    my $ip = $r->variable("remote_addr");
    my $reply = _request_nfwpunch($r, "revoke $ip web\n");

    return 502 if !defined($reply);

    if ($reply ne "OK revoked") {
        $r->log_error("nfwpunchd replied: $reply");
        return 403;
    }

    $r->send_http_header("text/html");
    $r->print("Access revoked\n");

    return 200;
}

1;
