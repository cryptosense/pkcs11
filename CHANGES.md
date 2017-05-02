v0.7.3 2017-05-02
=================

Tests:

- Add some functional tests that load a fake DLL (#39)

Build system:

- Support HP/UX (#40)
- Support OCaml 4.05 (#41)

v0.7.2 2017-04-14
=================

Changes:

- Do not use `Dl.RTLD_DEEPBIND` (#38)

Build system:

- Support FreeBSD builds (#37, thanks to Hannes Mehnert)

Documentation:

- Add an example application (#34, #35)

v0.7.1 2017-01-25
=================

Build system:

- Remove `records` from `META` to make it possible to actually use `pkcs11`
  without `records` installed (#33)

v0.7.0 2017-01-23
=================

Breaking changes:

- Remove `typ` values from `records`, deprecated in 0.6.0, and the associated
  dependency (#26)
- Rework the `P11_keys_attributes` module (#27):
  + rename it to `P11_key_attributes`
  + rename `possibles` to `possibles`
  + remove `kinds` and `is`
- Remove most "not implemented" attributes (#28, #29)

Fixes:

- Detect Linux hosts more robustly (#25)

New features:

- Provide optional `cmdliner` support through a new `Pkcs11_cli` module (in
  `pkcs11.cli`) (#31)

Build system:

- Forbid `key-parsers.0.6.0`
- Refer to the `Result` compatibility module only through a global `-open` (#30)
- Install `cmti` files (#32)
- Add missing `ounit` test-dependency (#32)

v0.6.0 2017-01-04
=================

Breaking changes:

- Removed deprecated operator aliases (#22)
- Remove the `P11_mechanisms` module (#23)
  + `kinds` is moved to `P11`
  + `key_type` can be replaced by `P11.Mechanism.key_type` (its results only
    depend on the mechanism type)

New features:

- Add yojson functions to several modules (#20)

Changes:

- `P11.Mechanism.key_type` is extended to non-keygen mechanisms.

Deprecated values:

- Deprecate `typ` values from `records` (#21).
  Users are expected to use the underlying `yojson` functions directly.
  The `records` dependency should be dropped in the next release.

Build system:

- Use docker for travis builds (#19)

v0.5.0 2016-12-16
=================

Breaking changes:

- `get_slot` return a result instead of raising an exception (#16)
- Make `P11.Mechanism.key_type` return an option (#17)

Cleanup:

- Fix warning 32 (#18)
- Fix warning 52 (#15)

Tests:

- Add tests for the bigint module (#14)

v0.4.0 2016-11-03
=================

Breaking changes:

- Changed the type of some low-level fields from `Ctypes.ptr` to
  `Ctypes_helpers.Reachable_ptr.t`. Those can be accessed using the `setf` and
  `getf` functions in the same module.
- Make `Pkcs11_data.t` abstract.

Fixes:

- Fix several use-after-free bugs (#10)

Build system:

- Add merlin configuration (#11)

v0.3.0 2016-10-18
=================

New features:

- Add inverted stubs (#8)

v0.2.0 2016-10-07
=================

Breaking changes:

- Rename `CK_PKCS5_PBKD2_DATA_PARAMS` to `CK_PKCS5_PBKD2_PARAMS` (#5)

New features:

- Install headers in ocamlfind directory (#2)

Changes:

- Improve documentation headers (#3)

v0.1.0 2016-09-22
=================

- Initial release.
