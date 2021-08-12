type t =
  | CKM of P11_mechanism_type.t
  | CK_UNAVAILABLE_INFORMATION
[@@deriving eq, ord, show]

let to_string = function
  | CKM x -> P11_mechanism_type.to_string x
  | CK_UNAVAILABLE_INFORMATION -> "CK_UNAVAILABLE_INFORMATION"

let of_string = function
  | "CK_UNAVAILABLE_INFORMATION" -> CK_UNAVAILABLE_INFORMATION
  | s -> CKM (P11_mechanism_type.of_string s)

let to_yojson mechanism_type =
  try `String (to_string mechanism_type) with
  | Invalid_argument _ -> `Null

let of_yojson =
  P11_helpers.of_json_string ~typename:"keygen mechanism" of_string
