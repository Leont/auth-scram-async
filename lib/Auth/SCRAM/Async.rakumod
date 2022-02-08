use v6.c;

unit module Auth::SCRAM::Async:ver<0.0.1>;

use Crypt::Random;
use OpenSSL::Digest;
use MIME::Base64;

enum Digest <SHA1 SHA256 SHA384 SHA512>;

my sub hmac-for(&digest, Int $block-size) {
	anon sub hmac (Blob $key is copy, Blob $message --> Blob) {
		$key = digest($key) if $key.elems > $block-size;
		my $inner-buf = digest((Blob.allocate($block-size, 0x36) ~^ $key) ~ $message);
		digest((Blob.allocate($block-size, 0x5c) ~^ $key) ~ $inner-buf);
	}
}

my %info-for{Digest} = (
	(SHA1)   => { :digest(&sha1),   :hash-size(20), :hmac(hmac-for(&sha1  ,  64)) },
	(SHA256) => { :digest(&sha256), :hash-size(32), :hmac(hmac-for(&sha256,  64)) },
	(SHA384) => { :digest(&sha384), :hash-size(48), :hmac(hmac-for(&sha384, 128)) },
	(SHA512) => { :digest(&sha512), :hash-size(64), :hmac(hmac-for(&sha512, 128)) },
);

my sub encode-name(Str $name) {
	$name.subst('=', '=3d', :g).subst(',', '=2c', :g);
}

my sub encode-base64(Blob $input) {
	MIME::Base64.encode($input, :oneline);
}

class Client {
	has Str:D $.username is required;
	has Str:D $.password is required;
	has Str $.authorization-id;
	has Digest:D $.digest is required;
	has &!digest = %info-for{$!digest}<digest>;
	has &!hmac   = %info-for{$!digest}<hmac>;
	has Int:D $.hash-size   = %info-for{$!digest}<hash-size>;
	has Int $.nonce-bits    = 192;
	has Blob $.client-nonce = crypt_random_buf($!nonce-bits div 8);
	has Str $!gs2-header    = 'n,' ~ ($!authorization-id ?? 'a=' ~ encode-name($!authorization-id) !! '') ~ ',';
	has Str $!client-first-payload    = 'n=' ~ encode-name($!username) ~ ',r=' ~ encode-base64($!client-nonce);
	has Int $.minimum-iterations = 4096;

	submethod TWEAK() {
		$!username = $!username.NFKC.Str;
		$!password = $!password.NFKC.Str;
		$!authorization-id = $!authorization-id.defined ?? $!authorization-id.NFKC.Str !! $!authorization-id;
	}

	has Blob $!server-key;
	has Blob $!authentication-message;

	method first-message(--> Str) {
		$!gs2-header ~ $!client-first-payload;
	}

	method !read-session(Str:D $input) {
		my %response;
		for $input.match(rx{ $<key>=<[a..z]> '=' $<value>=[<-[,]>+] }, :g) -> $/ {
			%response{$<key>} = ~$<value>;
		}
		%response;
	}

	method !derive(Blob $key, Blob $salt, Int $iter --> Blob) {
		my $previous = $salt;
		$previous.write-uint32($salt.elems, 1, BigEndian);

		my $result = Buf.new;
		for ^$iter {
			$previous = &!hmac($key, $previous);
			$result ~^= $previous;
		}
		$result
	}

	method final-message(Str:D $server-first --> Str) {
		my %response = self!read-session($server-first);
		die "Missing fields" unless %response{all(<r s i>)}:exists;
		die "Unsupported mandatry extentions" if %response<m>:exists;
		my $joined-nonce = MIME::Base64.decode(%response<r>);
		die "Incomplete nonce" if $joined-nonce.elems <= $!client-nonce.elems;
		die "Incomplete nonce" if $joined-nonce.subbuf(0, $!client-nonce.elems) ne $!client-nonce;

		my $salt = try MIME::Base64.decode(%response<s>);
		die "No salt given" without $salt;
		my $iters = try { %response<i>.Int } // 0;
		die "Too few iterations, $iters < $!minimum-iterations" if $iters < $!minimum-iterations;

		my $salted-password = self!derive($!password.encode, $salt, $iters);
		my $client-key = &!hmac($salted-password, "Client Key".encode);
		$!server-key = &!hmac($salted-password, "Server Key".encode);
		my $stored-key = &!digest($client-key);

		my $channel = 'c=' ~ encode-base64($!gs2-header.encode);
		my $nonce = "r=%response<r>";
		$!authentication-message = join(',', $!client-first-payload, $server-first, $channel, $nonce).encode;
		my $client-proof = &!hmac($stored-key, $!authentication-message);
		my $private = 'p=' ~ encode-base64($client-key ~^ $client-proof);

		join(',', $channel, $nonce, $private);
	}

	method validate(Str:D $server-final --> Bool) {
		my %response = self!read-session($server-final);
		return False unless %response<v>:exists;
		my $server-proof = &!hmac($!server-key, $!authentication-message);
		encode-base64($server-proof) eq %response<v>;
	}
}

=begin pod

=head1 NAME

Auth::SCRAM::Async - Salted Challenge Response Authentication Mechanism

=head1 SYNOPSIS

=begin code :lang<raku>

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

=end code

=head1 Description

This implements the Salted Challenge Response Authentication Mechanism.

=head1 Client

A client can be found as C<Auth::SCRAM::Async::Client>. It has the following methods:

=head2 new

This creates a new Auth::SCRAM::Async::Client object. Every handshake should use a fresh object.

=begin item2
Str :$username

Authentication identity. This will be normalized with the SASLprep algorithm before being transmitted to the server. This argument is mandatory.
=end item2

=begin item2
Str :$password

Authentication password. This will be normalized with the SASLprep algorithm before being transmitted to the server. This argument is mandatory.
=end item2

=begin item2
Str :$authorization-id

If the authentication identity (username) will act as a different, authorization identity, this attribute provides the authorization identity. It is optional. If not provided, the authentication identity is considered by the server to be the same as the authorization identity.
=end item2

=begin item2
Auth::SCRAM::Async::Digest :$digest

Identifier of a digest function. Valid values are C<Auth::SCRAM::Async::SHA1>, C<Auth::SCRAM::Async::SHA256>, C<Auth::SCRAM::Async::SHA384>, or C<Auth::SCRAM::Async::SHA512>. This argument is mandatory.
=end item2

=begin item2
Int :$minimum_iteration_count

If the server requests an iteration count less than this value, the client will reject it. This protects against downgrade attacks. The default is 4096, consistent with recommendations in the RFC.
=end item2

=begin item2
Int :$nonce-bits

Size of the client-generated nonce, in bits. Defaults to C<192>. The server-nonce will be appended, so the final nonce size will be substantially larger.
=end item2

=head2 first-message(--> Str)

This will return the opening message of a SCRAM handshake

=head2 final-message(Str $server-first --> Str)

This will process the first response from the server, and will generate the second message from the client.

=head2 validate(Str $server-final --> Bool)

This will validate the final response from the server, validating that they too know the shared secret.

=head1 Todo

=item1 Implement server side SCRAM.

=item1 Implement channel bindings.

=head1 See also

=item1 L<RFC5802|https://datatracker.ietf.org/doc/html/rfc5802> - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms

=item1 L<RFC7677|https://datatracker.ietf.org/doc/html/rfc7677> - SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms

=head1 Author

Leon Timmermans <fawaka@gmail.com>

=head1 Copyright and License

Copyright 2022 Leon Timmermans

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

=end pod
