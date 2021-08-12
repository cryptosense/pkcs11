# pkcs11 — Bindings to the PKCS#11 cryptographic API

[![Build Status][build_status_badge]][build_status_link]
[![Documentation][doc_badge]][doc_link]

PKCS#11 is an API used by smart cards and Hardware Security Modules to perform
cryptographic operations such as signature or encryption.

This library is made of several packages:

- `pkcs11`: type definitions corresponding to the PKCS#11 API
- `pkcs11-cli`: a library exposing Cmdliner arguments used to initiate a PKCS#11 session
- `pkcs11-driver`: bindings to emit calls to a PKCS#11 DLL
- `pkcs11-driver.fake`: a fake PKCS#11 DLL that returned hardcoded values, used for testing
- `pkcs11-rev`: reverse bindings to write OCaml PKCS#11 implementations

The entry point of this library is `P11.load_driver`. Examples are available in
`test/examples/`.

[build_status_badge]: https://github.com/cryptosense/pkcs11/actions/workflows/main.yml/badge.svg
[build_status_link]: https://github.com/cryptosense/pkcs11/actions/workflows/main.yml
[doc_badge]: https://img.shields.io/badge/doc-online-blue.svg
[doc_link]: https://cryptosense.github.io/pkcs11/doc/
