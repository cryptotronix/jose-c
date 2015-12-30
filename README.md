#libjosec

[![Build Status](https://travis-ci.org/cryptotronix/jose-c.png)](https://travis-ci.org/cryptotronix/jose-c)
<a href="https://scan.coverity.com/projects/4903">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/4903/badge.svg"/>
</a>

Currently supported mechanisms:

- HS256
- ES256

Supported JWE mechanisms (when built with openSSL):

- alg: A256KW, enc: A256GCM

## Why write yet another library, especially in C?!

The main reason I wrote this library is that I needed to work with
JWTs that are signed by embedded hardware--the software does not have
access to the key. Therefore, this library first has you create
function pointers to the sign and verify functions (if none is
provided, software signing is used).

You may also find this useful if you have your own crypto library that
you really want to use and the input to the signing function pointer
is the JWT signing input all ready to go.

Why C? I actually kinda like C. Emacs supports C nicely and I like
Emacs. Also, C works well for embedded systems still.

## Dependencies

The current required dependencies are:

- *check* for unit testing
- *jansson* for JSON parsing
- *yacl* for really [basic](https://github.com/cryptotronix/yacl)
  crypto.

There is an optional dependency on OpenSSL if you want to do AESKW and
AES-GCM.

The idea with yacl is to keep the code size down if one didn't
have/want OpenSSL. It's kinda a picking of raw crypto implementations,
kinda the thing you aren't supposed to do. I used to use gcrypt, which
I like but some people don't like LGPL. I would have gone with
WolfCrypto too, but again, GPL. Personally, I'm ok with LGPL stuff but
you know, life happens and we all make compromises.

Anyway, probably what I should do is just put the sha256 file in here
so there's no external depends.

## RFC7520 Tests

This library does not support all algorithms and RFC 7520 only
publishes test vectors for some algorithms. Therefore, the
intersection of supported algorithms by this library and published
test vectors is currently only HS256.


## License

The intent of this library is to dual license it as both LGPLv3 and
BSD-3. Currently, it's LGPGv3 because there are some cleanup issues I
need to perform to split it out nicely, but that's the idea.
