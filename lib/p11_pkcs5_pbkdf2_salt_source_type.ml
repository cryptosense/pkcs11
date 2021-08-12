type t = CKZ_SALT_SPECIFIED [@@deriving eq, ord, show]

let to_string = function
  | CKZ_SALT_SPECIFIED -> "CKZ_SALT_SPECIFIED"

let of_string = function
  | "CKZ_SALT_SPECIFIED" -> CKZ_SALT_SPECIFIED
  | _ -> invalid_arg "CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.of_string"

let to_yojson salt_type =
  try `String (to_string salt_type) with
  | Invalid_argument _ -> `Null

let of_yojson =
  P11_helpers.of_json_string ~typename:"salt source type" of_string
