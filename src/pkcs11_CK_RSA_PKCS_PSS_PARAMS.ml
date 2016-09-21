open Ctypes

type _t
type t = _t structure

let t : t typ = structure "CK_RSA_PKCS_PSS_PARAMS"

let (-:) ty label = Ctypes_helpers.smart_field t label ty
let hashAlg = Pkcs11_CK_MECHANISM_TYPE.typ -: "hashAlg"
let mgf = Pkcs11_CK_RSA_PKCS_MGF_TYPE.typ -: "mgf"
let sLen = ulong -: "sLen"
let () = seal t

type u =
  {
    hashAlg: Pkcs11_CK_MECHANISM_TYPE.u;
    mgf: Pkcs11_CK_RSA_PKCS_MGF_TYPE.t;
    sLen: Pkcs11_CK_ULONG.t;
  }

let make (u: u): t =
  let p = Ctypes.make t in
  setf p hashAlg @@ Pkcs11_CK_MECHANISM_TYPE.make u.hashAlg;
  setf p mgf u.mgf;
  setf p sLen u.sLen;
  p

let view (c: t): u =
  let hashAlg = Pkcs11_CK_MECHANISM_TYPE.view @@ getf c hashAlg in
  let mgf = getf c mgf in
  let sLen = getf c sLen in
  {
    hashAlg;
    mgf;
    sLen;
  }

let compare a b =
  let c = Pkcs11_CK_MECHANISM_TYPE.compare a.hashAlg b.hashAlg in
  if c <> 0 then
    c
  else
    let c = Unsigned.ULong.compare a.mgf b.mgf in
    if c <> 0 then
      c
    else
      Unsigned.ULong.compare a.sLen b.sLen
