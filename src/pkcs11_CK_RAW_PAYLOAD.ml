type t = Pkcs11_CK_MECHANISM_TYPE.t * string

let compare (a_ckm, a_param) (b_ckm, b_param) =
  let ua_ckm = Pkcs11_CK_MECHANISM_TYPE.view a_ckm in
  let ub_ckm = Pkcs11_CK_MECHANISM_TYPE.view b_ckm in
  if Pkcs11_CK_MECHANISM_TYPE.equal ua_ckm ub_ckm then
    String.compare a_param b_param
  else
    Pkcs11_CK_MECHANISM_TYPE.compare ua_ckm ub_ckm
