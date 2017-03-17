type t = Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.u

let to_string =
  Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.to_string

let of_string =
  Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.of_string

let to_yojson salt_type =
  try
    `String (to_string salt_type)
  with Invalid_argument _ ->
    `Null

let of_yojson = Ctypes_helpers.of_json_string ~typename:"salt source type" of_string
