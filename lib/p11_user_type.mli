type t =
  | CKU_SO
  | CKU_USER
  | CKU_CONTEXT_SPECIFIC
  | CKU_CS_UNKNOWN of P11_ulong.t
[@@deriving eq, ord, show, yojson]

val to_string : t -> string

val of_string : string -> t
