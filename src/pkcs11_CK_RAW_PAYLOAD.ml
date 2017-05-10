type t = Pkcs11_CK_MECHANISM_TYPE.t * string

let compare (a_ckm, a_param) (b_ckm, b_param) =
  let ua_ckm = Pkcs11_CK_MECHANISM_TYPE.view a_ckm in
  let ub_ckm = Pkcs11_CK_MECHANISM_TYPE.view b_ckm in
  if P11_mechanism_type.equal ua_ckm ub_ckm then
    String.compare a_param b_param
  else
    P11_mechanism_type.compare ua_ckm ub_ckm
