open Ctypes

type t = P11_ulong.t

let t : t typ = ulong

let ( ! ) x = Unsigned.ULong.of_string (Int64.to_string x)

let _CKD_NULL = !0x00000001L

let _CKD_SHA1_KDF = !0x00000002L

let make =
  let open P11_ec_kdf in
  function
  | CKD_NULL -> _CKD_NULL
  | CKD_SHA1_KDF -> _CKD_SHA1_KDF

let view ul =
  let open P11_ec_kdf in
  if ul = _CKD_NULL then
    CKD_NULL
  else if ul = _CKD_SHA1_KDF then
    CKD_SHA1_KDF
  else
    invalid_arg "CK_EC_KDF_TYPE.view"
