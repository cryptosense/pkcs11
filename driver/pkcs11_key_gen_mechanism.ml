type t = P11_ulong.t

let view x =
  let open P11_key_gen_mechanism in
  if P11_ulong.is_unavailable_information x then
    CK_UNAVAILABLE_INFORMATION
  else
    CKM (Pkcs11_CK_MECHANISM_TYPE.view x)

let make =
  let open P11_key_gen_mechanism in
  function
  | CKM x -> Pkcs11_CK_MECHANISM_TYPE.make x
  | CK_UNAVAILABLE_INFORMATION -> P11_ulong._CK_UNAVAILABLE_INFORMATION
