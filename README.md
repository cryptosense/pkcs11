`Pkcs11` - bindings to the PKCS#11 cryptographic API [![Build Status](https://travis-ci.org/cryptosense/pkcs11.svg?branch=master)](https://travis-ci.org/cryptosense/pkcs11) [![docs](https://img.shields.io/badge/doc-online-blue.svg)](https://cryptosense.github.io/pkcs11/doc/)
====================================================

PKCS11 is an API used by smartcards and Hardware Security Modules to perform
cryptographic operations such as signature or encryption.

This library contains several parts:
- `pkcs11`: type definitions corresponding to the PKCS#11 API
- `pkcs11.cli`: a library exposing cmdliner arguments used to initiate a PKCS#11 session
- `pkcs11.driver`: bindings to emit calls to a PKCS#11 dll
- `pkcs11.fake`: a fake pkcs11 dll that returned hardcoded values, used for testing
- `pkcs11.rev`: reverse bindings

The entry point of this library is [P11.load_driver]. Examples are available in
`test/examples/`.
