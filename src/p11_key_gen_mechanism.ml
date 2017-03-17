open Pkcs11.Key_gen_mechanism

type t = Pkcs11.Key_gen_mechanism.u =
  | CKM of P11_mechanism_type.t
  | CK_UNAVAILABLE_INFORMATION

let to_yojson mechanism_type =
  try
    `String (to_string mechanism_type)
  with Invalid_argument _ ->
    `Null

let of_yojson = Ctypes_helpers.of_json_string ~typename:"keygen mechanism" of_string
