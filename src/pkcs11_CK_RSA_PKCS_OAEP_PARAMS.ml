open Ctypes
open Ctypes_helpers

type source_type = Pkcs11_CK_ULONG.t
let source_type : source_type typ = ulong

let _CKZ_DATA_SPECIFIED    : source_type = Unsigned.ULong.of_int 0x00000001

type _t
type t = _t structure
let t : t typ = structure "CK_RSA_PKCS_OAEP_PARAMS"
let (-:) ty label = smart_field t label ty
let hashAlg = Pkcs11_CK_MECHANISM_TYPE.typ -: "hashAlg"
let mgf = Pkcs11_CK_RSA_PKCS_MGF_TYPE.typ -: "mgf"
let source  = source_type -: "source"
let pSourceData = Reachable_ptr.typ void -: "pSourceData"
let pSourceDataLen = ulong -: "pSourceDataLen"
let () = seal t

type u =
  {
    hashAlg: Pkcs11_CK_MECHANISM_TYPE.u [@compare Pkcs11_CK_MECHANISM_TYPE.compare];
    mgf: Pkcs11_CK_RSA_PKCS_MGF_TYPE.t;
    src: string option;
  }
[@@deriving ord]

let make (u: u): t =
  let src = u.src in
  let p = Ctypes.make t in
  setf p hashAlg @@ Pkcs11_CK_MECHANISM_TYPE.make u.hashAlg;
  setf p mgf u.mgf;
  setf p source _CKZ_DATA_SPECIFIED;
  make_string_option src p pSourceDataLen pSourceData;
  p

let view (c: t): u =
  { hashAlg = Pkcs11_CK_MECHANISM_TYPE.view @@ getf c hashAlg
  ; mgf = getf c mgf
  ; src = view_string_option c pSourceDataLen pSourceData
  }

let compare = [%ord: u]
