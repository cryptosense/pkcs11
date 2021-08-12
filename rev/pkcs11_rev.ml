module Make (X : Pkcs11.LOW_LEVEL_BINDINGS) =
  Pkcs11_rev_decl.Rev_bindings (X) (Pkcs11_rev_generated)
