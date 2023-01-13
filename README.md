rapido
===

rapido is a minimal implementation of TCPLS atop picotls. It follows the [TCPLS IETF draft](https://datatracker.ietf.org/doc/draft-piraux-tcpls/) specification.

Building rapido
---

If you have cloned rapido from git then ensure that you have initialised the submodules:
```
% git submodule update --init
```

Build using cmake:
```
% cmake .
% make rapido
% make check
```

Using the rapido command
---

Run the test server (at 127.0.0.1:8443):
```
% ./rapido -c /path/to/certificate.pem -k /path/to/private-key.pem  127.0.0.1 8443
```

Connect to the test server:
```
% ./rapido 127.0.0.1 8443
```

Other options are documented in the command:
```
% ./rapido -h
```

Public test server
---

We host a public server running an instance of the test server at 130.104.229.29 and 2001:6a8:308f:9:0:82ff:fe68:e51d on port 443. Be aware that it can only accept a single TCPLS session at a time. This test server is here for researchers to test their own implementation of TCPLS. After establishing a session, the server will continuously send data on its first stream until the client terminates the session.

To connect over IPv4 to the server:
```
./rapido -s 10 -n localhost 130.104.229.29 443
```

Documentation & API
---

The documentation and API can be found at https://mpiraux.github.io/rapido/. The `rapido.h` header file defines the functions and data structures available to the application leveraging TCPLS. 

picotls
===

Picotls is a [TLS 1.3 (RFC 8446)](https://tools.ietf.org/html/rfc8446) protocol stack written in C, with the following features:
* support for three crypto engines
  * "OpenSSL" backend using libcrypto for crypto and X.509 operations
  * "minicrypto" backend using [cifra](https://github.com/ctz/cifra) for most crypto and [micro-ecc](https://github.com/kmackay/micro-ecc) for secp256r1
  * ["fusion" AES-GCM engine, optimized for QUIC and other protocols that use short AEAD blocks](https://github.com/h2o/picotls/pull/310)
* support for PSK, PSK-DHE resumption using 0-RTT
* API for dealing directly with TLS handshake messages (essential for QUIC)
* supported extensions:
  * RFC 7250 (raw public keys)
  * RFC 8879 (certificate compression)
  * Encrypted SNI (wg-draft-02)

Primary goal of the project is to create a fast, tiny, low-latency TLS 1.3 implementation that can be used with the HTTP/2 protocol stack and the upcoming QUIC stack of the [H2O HTTP/2 server](https://h2o.examp1e.net).

The TLS protocol implementation of picotls is licensed under the MIT license.

License and the cryptographic algorithms supported by the crypto bindings are as follows:

| Binding | License | Key Exchange | Certificate | AEAD cipher |
|:-----:|:-----:|:-----:|:-----:|:-----:|
| minicrypto | [CC0](https://github.com/ctz/cifra/) / [2-clause BSD](https://github.com/kmackay/micro-ecc) | secp256r1, x25519 | ECDSA (secp256r1)<sup>1</sup> | AES-128-GCM, chacha20-poly1305 |
| OpenSSL | OpenSSL | secp256r1, secp384r1, secp521r1, x25519 | RSA, ECDSA (secp256r1, secp384r1, secp521r1), ed25519 | AES-128-GCM, AES-256-GCM, chacha20-poly1305 |

Note 1: Minicrypto binding is capable of signing a handshake using the certificate's key, but cannot verify a signature sent by the peer.

Building picotls
---

If you have cloned picotls from git then ensure that you have initialised the submodules:
```
% git submodule init
% git submodule update
```

Build using cmake:
```
% cmake .
% make
% make check
```

A dedicated documentation for using picotls with Visual Studio can be found in [WindowsPort.md](WindowsPort.md).

Developer documentation
---

Developer documentation should be available on [the wiki](https://github.com/h2o/picotls/wiki).

Using the cli command
---

Run the test server (at 127.0.0.1:8443):
```
% ./cli -c /path/to/certificate.pem -k /path/to/private-key.pem  127.0.0.1 8443
```

Connect to the test server:
```
% ./cli 127.0.0.1 8443
```

Using resumption:
```
% ./cli -s session-file 127.0.0.1 8443
```
The session-file is read-write.
The cli server implements a single-entry session cache.
The cli server sends NewSessionTicket when it first sends application data after receiving ClientFinished.

Using early-data:
```
% ./cli -s session-file -e 127.0.0.1 8443
```
When `-e` option is used, client first waits for user input, and then sends CLIENT_HELLO along with the early-data.

License
---

The software is provided under the MIT license.
Note that additional licences apply if you use the minicrypto binding (see above).
