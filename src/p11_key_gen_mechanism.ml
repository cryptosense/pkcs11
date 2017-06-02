type t =
  | CKM of P11_mechanism_type.t
  | CK_UNAVAILABLE_INFORMATION

let compare a b = match a, b with
  | CK_UNAVAILABLE_INFORMATION, CK_UNAVAILABLE_INFORMATION -> 0
  | CKM x , CKM y -> P11_mechanism_type.compare x y
  | CKM _, CK_UNAVAILABLE_INFORMATION -> 1
  | CK_UNAVAILABLE_INFORMATION, CKM _ -> -1

let to_string = function
  | CKM x -> P11_mechanism_type.to_string x
  | CK_UNAVAILABLE_INFORMATION -> "CK_UNAVAILABLE_INFORMATION"

let of_string = function
  | "CK_UNAVAILABLE_INFORMATION" -> CK_UNAVAILABLE_INFORMATION
  | s -> CKM (P11_mechanism_type.of_string s)

let to_yojson mechanism_type =
  try
    `String (to_string mechanism_type)
  with Invalid_argument _ ->
    `Null

let of_yojson = Pkcs11_helpers.of_json_string ~typename:"keygen mechanism" of_string
