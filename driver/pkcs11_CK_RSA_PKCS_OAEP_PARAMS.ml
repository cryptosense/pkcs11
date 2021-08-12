open Ctypes
open Ctypes_helpers

type source_type = P11_ulong.t

let source_type : source_type typ = ulong

let _CKZ_DATA_SPECIFIED : source_type = Unsigned.ULong.of_int 0x00000001

type _t

type t = _t structure

let t : t typ = structure "CK_RSA_PKCS_OAEP_PARAMS"

let ( -: ) ty label = smart_field t label ty

let hashAlg = Pkcs11_CK_MECHANISM_TYPE.typ -: "hashAlg"

let mgf = Pkcs11_CK_RSA_PKCS_MGF_TYPE.typ -: "mgf"

let source = source_type -: "source"

let pSourceData = Reachable_ptr.typ void -: "pSourceData"

let pSourceDataLen = ulong -: "pSourceDataLen"

let () = seal t

let make params =
  let open P11_rsa_pkcs_oaep_params in
  let src = params.src in
  let p = Ctypes.make t in
  setf p hashAlg @@ Pkcs11_CK_MECHANISM_TYPE.make params.hashAlg;
  setf p mgf params.mgf;
  setf p source _CKZ_DATA_SPECIFIED;
  make_string_option src p pSourceDataLen pSourceData;
  p

let view c =
  let open P11_rsa_pkcs_oaep_params in
  { hashAlg = Pkcs11_CK_MECHANISM_TYPE.view @@ getf c hashAlg
  ; mgf = getf c mgf
  ; src = view_string_option c pSourceDataLen pSourceData }
