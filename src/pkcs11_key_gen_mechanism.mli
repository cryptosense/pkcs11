(** Parameters for [CKA_KEY_GEN_MECHANISM] *)
type t = Pkcs11_CK_ULONG.t

val make : P11_key_gen_mechanism.t -> t

val view : t -> P11_key_gen_mechanism.t
