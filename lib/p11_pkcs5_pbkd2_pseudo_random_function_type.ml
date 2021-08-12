type t = CKP_PKCS5_PBKD2_HMAC_SHA1 [@@deriving eq, ord, show]

let to_string = function
  | CKP_PKCS5_PBKD2_HMAC_SHA1 -> "CKP_PKCS5_PBKD2_HMAC_SHA1"

let of_string = function
  | "CKP_PKCS5_PBKD2_HMAC_SHA1" -> CKP_PKCS5_PBKD2_HMAC_SHA1
  | _ -> invalid_arg "CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.of_string"

let to_yojson prf_type =
  try `String (to_string prf_type) with
  | Invalid_argument _ -> `Null

let of_yojson =
  P11_helpers.of_json_string ~typename:"random function type" of_string
