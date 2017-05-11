type t =
  | CKM of P11_mechanism_type.t
  | CK_UNAVAILABLE_INFORMATION 
[@@deriving ord,yojson]

val to_string : t -> string

val of_string : string -> t
