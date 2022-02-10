[![Actions Status](https://github.com/Leont/auth-scram-async/workflows/test/badge.svg)](https://github.com/Leont/auth-scram-async/actions)

NAME
====

Auth::SCRAM::Async - Salted Challenge Response Authentication Mechanism

SYNOPSIS
========

```raku
use Auth::SCRAM::Async;

my $client = Auth::SCRAM::Async::Client.new(:$username, :$password, :type(Auth::SCRAM::Async::SHA256));
my $client-first = $client.first-message;
send-message($client-first);

my $server-first = read-response();
with $client.final-message($server-first) -> $client-final {
	send-message($client-final);

	my $server-final = read-response();
	say "success" if $client.validate($server-final);
}
```

Description
===========

This implements the Salted Challenge Response Authentication Mechanism.

Client
======

A client can be found as `Auth::SCRAM::Async::Client`. It has the following methods:

new
---

This creates a new Auth::SCRAM::Async::Client object. Every handshake should use a fresh object.

    * Str :$username

      Authentication identity. This will be normalized with the SASLprep algorithm before being transmitted to the server. This argument is mandatory.

    * Str :$password

      Authentication password. This will be normalized with the SASLprep algorithm before being transmitted to the server. This argument is mandatory.

    * Str :$authorization-id

      If the authentication identity (username) will act as a different, authorization identity, this attribute provides the authorization identity. It is optional. If not provided, the authentication identity is considered by the server to be the same as the authorization identity.

    * Auth::SCRAM::Async::Digest :$digest

      Identifier of a digest function. Valid values are `Auth::SCRAM::Async::SHA1`, `Auth::SCRAM::Async::SHA256`, `Auth::SCRAM::Async::SHA384`, or `Auth::SCRAM::Async::SHA512`. This argument is mandatory.

    * Int :$minimum_iteration_count

      If the server requests an iteration count less than this value, the client will reject it. This protects against downgrade attacks. The default is 4096, consistent with recommendations in the RFC.

    * Int :$nonce-bits

      Size of the client-generated nonce, in bits. Defaults to `192`. The server-nonce will be appended, so the final nonce size will be substantially larger.

first-message(--> Str)
----------------------

This will return the opening message of a SCRAM handshake

final-message(Str $server-first --> Str)
----------------------------------------

This will process the first response from the server, and will generate the second message from the client.

validate(Str $server-final --> Bool)
------------------------------------

This will validate the final response from the server, validating that they too know the shared secret.

Todo
====

  * Implement server side SCRAM.

  * Implement channel bindings.

See also
========

  * [RFC5802](https://datatracker.ietf.org/doc/html/rfc5802) - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms

  * [RFC7677](https://datatracker.ietf.org/doc/html/rfc7677) - SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms

Author
======

Leon Timmermans <fawaka@gmail.com>

Copyright and License
=====================

Copyright 2022 Leon Timmermans

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

