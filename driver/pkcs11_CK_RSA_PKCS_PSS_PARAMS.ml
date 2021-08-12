open Ctypes

type _t

type t = _t structure

let t : t typ = structure "CK_RSA_PKCS_PSS_PARAMS"

let ( -: ) ty label = Ctypes_helpers.smart_field t label ty

let hashAlg = Pkcs11_CK_MECHANISM_TYPE.typ -: "hashAlg"

let mgf = Pkcs11_CK_RSA_PKCS_MGF_TYPE.typ -: "mgf"

let sLen = ulong -: "sLen"

let () = seal t

let make params =
  let open P11_rsa_pkcs_pss_params in
  let p = Ctypes.make t in
  setf p hashAlg @@ Pkcs11_CK_MECHANISM_TYPE.make params.hashAlg;
  setf p mgf params.mgf;
  setf p sLen params.sLen;
  p

let view c =
  let hashAlg = Pkcs11_CK_MECHANISM_TYPE.view @@ getf c hashAlg in
  let mgf = getf c mgf in
  let sLen = getf c sLen in
  P11_rsa_pkcs_pss_params.{hashAlg; mgf; sLen}
