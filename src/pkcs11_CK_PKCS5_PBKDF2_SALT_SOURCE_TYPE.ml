type t = Pkcs11_CK_ULONG.t

let (!) x  = Unsigned.ULong.of_string (Int64.to_string x)

let _CKZ_SALT_SPECIFIED : t = ! 0x00000001L

type u =
  | CKZ_SALT_SPECIFIED

let (==) a b = Unsigned.ULong.compare a b = 0

let equal = (Pervasives.(=): u -> u -> bool)
let compare = (Pervasives.compare: u -> u -> int)

let to_string = function
  | CKZ_SALT_SPECIFIED -> "CKZ_SALT_SPECIFIED"

let of_string = function
  | "CKZ_SALT_SPECIFIED" -> CKZ_SALT_SPECIFIED
  | _ -> invalid_arg "CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.of_string"

let view ul =
  if ul == _CKZ_SALT_SPECIFIED then CKZ_SALT_SPECIFIED else
    invalid_arg ("Unknown CKP code: " ^ Unsigned.ULong.to_string ul)

let make = function
  | CKZ_SALT_SPECIFIED -> _CKZ_SALT_SPECIFIED

let typ = Ctypes.ulong
