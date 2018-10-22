`Pkcs11` - bindings to the PKCS#11 cryptographic API [![Build Status](https://travis-ci.org/cryptosense/pkcs11.svg?branch=master)](https://travis-ci.org/cryptosense/pkcs11) [![docs](https://img.shields.io/badge/doc-online-blue.svg)](https://cryptosense.github.io/pkcs11/doc/)
====================================================

PKCS11 is an API used by smartcards and Hardware Security Modules to perform
cryptographic operations such as signature or encryption.

This library contains two parts: type definitions corresponding to the PKCS#11
API, and bindings using `ctypes` to emit calls to a DLL.

To install the driver part, install `ctypes` and `ctypes-foreign` - it will
build a `pkcs11.driver` package.

The entry point of this library is [P11.load_driver]. An example is available in
`test/examples/example_sign.ml`.
