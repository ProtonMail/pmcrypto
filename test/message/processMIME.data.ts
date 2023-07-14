export const key = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v4.4.6
Comment: https://openpgpjs.org

xjMEXG6rNhYJKwYBBAHaRw8BAQdA63eiHJ6ylmHXwDzvNoBXDx3UkaF6rm3d
kToIFs8KYGnNG0pvbiBTbWl0aCA8am9uQGV4YW1wbGUuY29tPsJ3BBAWCgAf
BQJcbqs2BgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAKCRACmBrNmWu7s6ig
AP4l4JUNFYP1lzje4+VB1oz3xgAJwDpIPnpvV4p6fVfCMQEAsfqvA6OdgLl+
MmVRBRXO1BUtkSxwS9zxzQfE/0NZ7QfOOARcbqs2EgorBgEEAZdVAQUBAQdA
4IcImEOmtilzNy6BvjyoHHtiukYZlb4/38iqQbzQxywDAQgHwmEEGBYIAAkF
AlxuqzYCGwwACgkQApgazZlru7OCeAD/Waa1g7t1DsrE8Di+ovD19Xs7js4R
82uvdzLBXafN8okBALL5uHCjG/gkJzHGun2Tj2MKO2ykR6gv6lVKo7jX75kD
=7vY3
-----END PGP PUBLIC KEY BLOCK-----`;

export const multipartSignedMessage = `From: Jon Smith <jon@example.com>
To: Jon Smith <jon@example.com>
Mime-Version: 1.0
Content-Type: multipart/signed; boundary=bar; micalg=pgp-md5;
protocol="application/pgp-signature"

--bar
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1Hola!

Did you know that talking to yourself is a sign of senility?

It's generally a good idea to encode lines that begin with
From=20because some mail transport agents will insert a greater-
than (>) sign, thus invalidating the signature.

Also, in some cases it might be desirable to encode any   =20
trailing whitespace that occurs on lines in order to ensure  =20
that the message signature is not invalidated when passing =20
a gateway that modifies such whitespace (like BITNET). =20

me   
--bar

Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js v4.4.6
Comment: https://openpgpjs.org

wl4EARYKAAYFAlxurnwACgkQApgazZlru7OZ4gEA7gcIhNDZe9DurcA7I6Hb
J+mJL9vKtB5Ob4ponog5+ZYBAK6MCfmEImVCpdOlAIKmA9VRzQVLbW+Zm9cc
iwVC3WsC
=beyW
-----END PGP SIGNATURE-----

--bar--`;

export const invalidMultipartSignedMessage = `From: Jon Smith <jon@example.com>
To: Jon Smith <jon@example.com>
Mime-Version: 1.0
Content-Type: multipart/signed; boundary=bar; micalg=pgp-md5;
protocol="application/pgp-signature"

--bar
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

message with missing signature
--bar
`;

export const multipartSignedMessageBody = `¡Hola!

Did you know that talking to yourself is a sign of senility?

It's generally a good idea to encode lines that begin with
From because some mail transport agents will insert a greater-
than (>) sign, thus invalidating the signature.

Also, in some cases it might be desirable to encode any    
trailing whitespace that occurs on lines in order to ensure   
that the message signature is not invalidated when passing  
a gateway that modifies such whitespace (like BITNET).  

me`;

export const extraMultipartSignedMessage = `From: Jon Smith <jon@example.com>
To: Jon Smith <jon@example.com>
Mime-Version: 1.0
Content-Type: multipart/signed; boundary=bar; micalg=pgp-md5;
protocol="application/pgp-signature"

--bar
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

hello
--bar

Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js v4.4.6
Comment: https://openpgpjs.org

wl4EARYKAAYFAlxuurAACgkQApgazZlru7PubwEAkm2yNgMcCzv9YuW2zKEP
eo6TtHjWxF3GASwuZ/nMv/MBAJUDDC3PDfCIGyPKk2Pzf2t2co/+dEpW3vpx
euiL4uYD
=97+O
-----END PGP SIGNATURE-----

--bar
extra part
--bar--`;

export const multiPartMessageWithSpecialCharacter = `From: Jon Smith <jon@example.com>
To: Jon Smith <jon@example.com>
Mime-Version: 1.0
Content-Type: multipart/signed; boundary==-=pj+EhsWuSQJxx7=-=; micalg=pgp-md5;
protocol="application/pgp-signature"

--=-=pj+EhsWuSQJxx7=-=
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

hello
--=-=pj+EhsWuSQJxx7=-=

Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
Version: OpenPGP.js v4.4.6
Comment: https://openpgpjs.org

wl4EARYKAAYFAlxuurAACgkQApgazZlru7PubwEAkm2yNgMcCzv9YuW2zKEP
eo6TtHjWxF3GASwuZ/nMv/MBAJUDDC3PDfCIGyPKk2Pzf2t2co/+dEpW3vpx
euiL4uYD
=97+O
-----END PGP SIGNATURE-----

--=-=pj+EhsWuSQJxx7=-=
`;

// Message from: https://docs.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2010/aa563375(v=exchg.140)
export const multipartMessageWithAttachment = `From: Some One <someone@example.com>
To: "Someone Else" <someone-else@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XXXXboundary text"

This is a multipart message in MIME format.

--XXXXboundary text
Content-Type: text/plain

this is the body text

--XXXXboundary text
Content-Type: text/plain;
Content-Disposition: attachment; filename="test.txt"

this is the attachment text

--XXXXboundary text--`;

// NB: this message signature is invalid and not verifiable using `key`.
export const multipartMessageWithEncryptedSubject = `From: "Some One" <someone@example.com>
To: "Someone Else" <someone-else@example.com>
Subject: ...
Mime-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="------------w7atwMAiUaHQsKDKV5d0o0kr"

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--------------w7atwMAiUaHQsKDKV5d0o0kr
Content-Type: multipart/mixed; boundary="------------nUB097wGzA443Ku03aYWQKqa"; protected-headers="v1"
Subject: Encrypted subject
From: "Some One" <someone@example.com>
To: "Someone Else" <someone-else@example.com>

--------------nUB097wGzA443Ku03aYWQKqa
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

hello
--------------nUB097wGzA443Ku03aYWQKqa--

--------------w7atwMAiUaHQsKDKV5d0o0kr
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmIwlfMAIQkQdqGsuYvE1jgWIQRGvajOG9a8ZbdysiN2oay5
i8TWOBX5AP0V5H79/eiraXKKBCvpqwcEzrv1DHfhvrjTHk9L6PIadgD/fXdv
WTyjgksKkPV68HhW1CIKZ4JIMe726uldjP6tgw8=
=nHao
-----END PGP SIGNATURE-----

--------------w7atwMAiUaHQsKDKV5d0o0kr--`;

export const multipartMessageWithUnnamedAttachments = `From: Some One <someone@example.com>
To: "Someone Else" <someone-else@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XXXXboundary text"

This is a multipart message in MIME format.

--XXXXboundary text
Content-Type: text/plain

this is the body text

--XXXXboundary text
Content-Type: text/plain;
Content-Disposition: attachment;

this is the first attachment text

--XXXXboundary text
Content-Type: text/plain;
Content-Disposition: attachment;

this is the second attachment text

--XXXXboundary text--`;

// NB: this message signature is invalid and not verifiable using `key`.
export const multipartMessageWithEncryptedSubjectUTF8 = `Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="------------3mBgKY4DhzDe0cOovVcT4QQv"

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--------------3mBgKY4DhzDe0cOovVcT4QQv
Content-Type: multipart/mixed; boundary="------------7VgK7B2dk0pUYjHBY0Zi2Fda";
 protected-headers="v1"
Subject: =?UTF-8?B?c3ViamVjdCB3aXRoIGVtb2ppcyDwn5iD8J+Yhw==?=
From: Sender <sender@example.com>
To: receiver@example.com
Message-ID: <7daafa18-8595-8065-3eba-b08c07becf36@example.com>

--------------7VgK7B2dk0pUYjHBY0Zi2Fda
Content-Type: multipart/mixed; boundary="------------D5jH01SvFZAwYShsjQamYW8w"

--------------D5jH01SvFZAwYShsjQamYW8w
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: base64

dGVzdCB1dGY4IGluIGVuY3J5cHRlZCBzdWJqZWN0DQo=
--------------D5jH01SvFZAwYShsjQamYW8w
Content-Type: application/pgp-keys; name="OpenPGP_0xabc.asc"
Content-Disposition: attachment; filename="OpenPGP_0xabc.asc"
Content-Description: OpenPGP public key
Content-Transfer-Encoding: quoted-printable

-----BEGIN PGP PUBLIC KEY BLOCK-----

...
-----END PGP PUBLIC KEY BLOCK-----

--------------D5jH01SvFZAwYShsjQamYW8w--

--------------7VgK7B2dk0pUYjHBY0Zi2Fda--

--------------3mBgKY4DhzDe0cOovVcT4QQv
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmIwlfMAIQkQdqGsuYvE1jgWIQRGvajOG9a8ZbdysiN2oay5
i8TWOBX5AP0V5H79/eiraXKKBCvpqwcEzrv1DHfhvrjTHk9L6PIadgD/fXdv
WTyjgksKkPV68HhW1CIKZ4JIMe726uldjP6tgw8=
=nHao
-----END PGP SIGNATURE-----

--------------3mBgKY4DhzDe0cOovVcT4QQv--
`;

export const messageWithEmptyBody = `Content-Type: multipart/mixed; boundary="------------P7E1gxp6rCvfn0to5n3PZ2h0";
protected-headers="v1"
From: Sender <sender@test.com>
To: receiver@pm.me
Message-ID: <39b3134c-0fcd-4618-b1bd-2b20481bf2af>
Subject: Empty message test

--------------P7E1gxp6rCvfn0to5n3PZ2h0
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit


--------------P7E1gxp6rCvfn0to5n3PZ2h0--`;
