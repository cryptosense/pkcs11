open Ctypes

type t = Pkcs11_CK_ULONG.t

let (!) x  = Unsigned.ULong.of_string (Int64.to_string x)

let _CKP_PKCS5_PBKD2_HMAC_SHA1 : t = ! 0x00000001L

type u =
  | CKP_PKCS5_PBKD2_HMAC_SHA1

let (==) a b = Unsigned.ULong.compare a b = 0

let to_string = function
  | CKP_PKCS5_PBKD2_HMAC_SHA1 -> "CKP_PKCS5_PBKD2_HMAC_SHA1"

let of_string = function
  | "CKP_PKCS5_PBKD2_HMAC_SHA1" -> CKP_PKCS5_PBKD2_HMAC_SHA1
  | _ -> invalid_arg "CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.of_string"

let view ul =
  if ul == _CKP_PKCS5_PBKD2_HMAC_SHA1 then CKP_PKCS5_PBKD2_HMAC_SHA1 else
    invalid_arg ("Unknown CKP code: " ^ Unsigned.ULong.to_string ul)

let make = function
  | CKP_PKCS5_PBKD2_HMAC_SHA1 -> _CKP_PKCS5_PBKD2_HMAC_SHA1

let typ = ulong
