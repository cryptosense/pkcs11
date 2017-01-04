(** Information about mechanisms *)

(** Support missing for a given mechanism in [key_type].  *)
exception Mechanism_not_supported of string

(** Return the key type associated to a given mechanism. May raise
    [Mechanism_not_supported] because the implementation of [key_type]
    is partial. Some mechanisms do not have associated key types
    (e.g., hash algorithms). *)
val key_type: Pkcs11.CK_MECHANISM_TYPE.u -> Pkcs11.CK_KEY_TYPE.u option
