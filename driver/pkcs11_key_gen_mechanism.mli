(** Parameters for [CKA_KEY_GEN_MECHANISM] *)
type t = P11_ulong.t

val make : P11_key_gen_mechanism.t -> t

val view : t -> P11_key_gen_mechanism.t
