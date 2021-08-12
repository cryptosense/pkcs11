type t = P11_ulong.t [@@deriving eq, ord]

let ( ! ) x = Unsigned.ULong.of_string (Int64.to_string x)

let _CKZ_SALT_SPECIFIED : t = !0x00000001L

let view ul =
  let open P11_pkcs5_pbkdf2_salt_source_type in
  if ul == _CKZ_SALT_SPECIFIED then
    CKZ_SALT_SPECIFIED
  else
    invalid_arg ("Unknown CKP code: " ^ Unsigned.ULong.to_string ul)

let make =
  let open P11_pkcs5_pbkdf2_salt_source_type in
  function
  | CKZ_SALT_SPECIFIED -> _CKZ_SALT_SPECIFIED

let typ = Ctypes.ulong
