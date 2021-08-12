open Ctypes
open Ctypes_helpers

type _t

type t = _t structure

let t : t typ = structure "CK_ECDH1_DERIVE_PARAMS"

let ( -: ) typ label = smart_field t label typ

let kdf = Pkcs11_CK_EC_KDF_TYPE.t -: "kdf"

let ulSharedDataLen = ulong -: "ulSharedDataLen"

let pSharedData = Reachable_ptr.typ Pkcs11_CK_BYTE.typ -: "pSharedData"

let ulPublicDataLen = ulong -: "ulPublicDataLen"

let pPublicData = Reachable_ptr.typ Pkcs11_CK_BYTE.typ -: "pPublicData"

let () = seal t

let make u =
  let open P11_ecdh1_derive_params in
  let p = Ctypes.make t in
  setf p kdf @@ Pkcs11_CK_EC_KDF_TYPE.make u.kdf;
  make_string_option u.shared_data p ulSharedDataLen pSharedData;
  make_string u.public_data p ulPublicDataLen pPublicData;
  p

let view p =
  let open P11_ecdh1_derive_params in
  { kdf = Pkcs11_CK_EC_KDF_TYPE.view @@ getf p kdf
  ; shared_data = view_string_option p ulSharedDataLen pSharedData
  ; public_data = view_string p ulPublicDataLen pPublicData }
