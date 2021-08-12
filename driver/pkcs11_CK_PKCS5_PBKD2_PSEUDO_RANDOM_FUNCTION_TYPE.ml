type t = P11_ulong.t [@@deriving eq]

let ( ! ) x = Unsigned.ULong.of_string (Int64.to_string x)

let _CKP_PKCS5_PBKD2_HMAC_SHA1 : t = !0x00000001L

let view ul =
  if equal ul _CKP_PKCS5_PBKD2_HMAC_SHA1 then
    P11_pkcs5_pbkd2_pseudo_random_function_type.CKP_PKCS5_PBKD2_HMAC_SHA1
  else
    invalid_arg ("Unknown CKP code: " ^ Unsigned.ULong.to_string ul)

let make =
  let open P11_pkcs5_pbkd2_pseudo_random_function_type in
  function
  | CKP_PKCS5_PBKD2_HMAC_SHA1 -> _CKP_PKCS5_PBKD2_HMAC_SHA1

let typ = Ctypes.ulong
