(** Mechanisms in a not-decoded form *)
type t = Pkcs11_CK_MECHANISM_TYPE.t * string

val compare : t -> t -> int
