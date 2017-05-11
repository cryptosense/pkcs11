type t = Pkcs11_CK_ULONG.t

let (!) x  = Unsigned.ULong.of_string (Int64.to_string x)

let _CKP_PKCS5_PBKD2_HMAC_SHA1 : t = ! 0x00000001L

let (==) a b = Unsigned.ULong.compare a b = 0

let view ul =
  let open P11_pkcs5_pbkd2_pseudo_random_function_type in
  if ul == _CKP_PKCS5_PBKD2_HMAC_SHA1 then CKP_PKCS5_PBKD2_HMAC_SHA1 else
    invalid_arg ("Unknown CKP code: " ^ Unsigned.ULong.to_string ul)

let make =
  let open P11_pkcs5_pbkd2_pseudo_random_function_type in
  function
  | CKP_PKCS5_PBKD2_HMAC_SHA1 -> _CKP_PKCS5_PBKD2_HMAC_SHA1

let typ = Ctypes.ulong
