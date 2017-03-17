type t = Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.u

let to_string =
  Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.to_string

let of_string =
  Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.of_string

let to_yojson prf_type =
  try
    `String (to_string prf_type)
  with Invalid_argument _ ->
    `Null

let of_yojson = Ctypes_helpers.of_json_string ~typename:"random function type" of_string
