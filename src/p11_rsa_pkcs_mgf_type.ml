include Pkcs11.CK_RSA_PKCS_MGF_TYPE

let to_json key_type =
  try
    `String (to_string key_type)
  with Invalid_argument _ ->
    `Null

let to_yojson = to_json
let of_yojson = Ctypes_helpers.of_json_string ~typename:"MGF type" of_string
