(** Mechanisms in a not-decoded form *)
type t = Pkcs11_CK_MECHANISM_TYPE.t * string
[@@deriving ord]

val make : P11_raw_payload_params.t -> t

val view : t -> P11_raw_payload_params.t
