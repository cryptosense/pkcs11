open Ctypes

type t = Pkcs11_CK_ULONG.t
let t : t typ = ulong

let (!) x  = Unsigned.ULong.of_string (Int64.to_string x)
let _CKD_NULL     = !0x00000001L
let _CKD_SHA1_KDF = !0x00000002L

type u =
  | CKD_NULL
  | CKD_SHA1_KDF
  [@@deriving yojson]

let make = function
  | CKD_NULL     -> _CKD_NULL
  | CKD_SHA1_KDF -> _CKD_SHA1_KDF

let view ul =
  if ul = _CKD_NULL     then CKD_NULL
  else if ul = _CKD_SHA1_KDF then CKD_SHA1_KDF
  else invalid_arg "CK_EC_KDF_TYPE.view"
