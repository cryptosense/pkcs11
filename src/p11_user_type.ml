type t = Pkcs11.CK_USER_TYPE.u =
  | CKU_SO
  | CKU_USER
  | CKU_CONTEXT_SPECIFIC
  | CKU_CS_UNKNOWN of Unsigned.ULong.t

let compare x y = Pkcs11.CK_USER_TYPE.compare x y
let equal x y = Pkcs11.CK_USER_TYPE.equal x y
let to_string : t -> string = Pkcs11.CK_USER_TYPE.to_string
let of_string : string -> t = Pkcs11.CK_USER_TYPE.of_string

let to_yojson user_type =
  `String (to_string user_type)

let of_yojson = Ctypes_helpers.of_json_string ~typename:"user type" of_string
