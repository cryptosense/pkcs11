type t = Pkcs11_CK_ULONG.t

let view x =
  let open P11_key_gen_mechanism in
  if Pkcs11_CK_ULONG.is_unavailable_information x
  then CK_UNAVAILABLE_INFORMATION
  else CKM (Pkcs11_CK_MECHANISM_TYPE.view x)

let make =
  let open P11_key_gen_mechanism in
  function
  | CKM x -> Pkcs11_CK_MECHANISM_TYPE.make x
  | CK_UNAVAILABLE_INFORMATION -> Pkcs11_CK_ULONG._CK_UNAVAILABLE_INFORMATION
