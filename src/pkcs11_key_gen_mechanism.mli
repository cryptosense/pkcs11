(** Parameters for [CKA_KEY_GEN_MECHANISM] *)
type t = Pkcs11_CK_ULONG.t

type u =
  | CKM of P11_mechanism_type.t
  | CK_UNAVAILABLE_INFORMATION
val to_string : u -> string
val of_string : string -> u
val make : u -> t
val view : t -> u
val compare : u -> u -> int
