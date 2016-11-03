open Ctypes
open Ctypes_helpers

type _t
type t = _t structure
let t : t typ = structure "CK_ECMQV_DERIVE_PARAMS"

let (-:) typ label = smart_field t label typ
let kdf              = Pkcs11_CK_EC_KDF_TYPE.t -: "kdf"
let ulSharedDataLen  = ulong            -: "ulSharedDataLen"
let pSharedData      = Reachable_ptr.typ char -: "pSharedData"
let ulPublicDataLen  = ulong            -: "ulPublicDataLen"
let pPublicData      = Reachable_ptr.typ char         -: "pPublicData"
let ulPrivateDataLen = ulong            -: "ulPrivateDataLen"
let hPrivateData     = Pkcs11_CK_OBJECT_HANDLE.typ -: "hPrivateData"
let ulPublicDataLen2 = ulong            -: "ulPublicDataLen2"
let pPublicData2     = Reachable_ptr.typ char -: "pPublicData2"
let publicKey        = Pkcs11_CK_OBJECT_HANDLE.typ -: "publicKey"
let () = seal t

type u =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: string
  ; private_data_len: Pkcs11_CK_ULONG.t
  ; private_data: Pkcs11_CK_OBJECT_HANDLE.t
  ; public_data2: string
  ; public_key: Pkcs11_CK_OBJECT_HANDLE.t
  }

let make u =
  let p = Ctypes.make t in
  setf p kdf @@ Pkcs11_CK_EC_KDF_TYPE.make u.kdf;
  make_string_option u.shared_data p ulSharedDataLen pSharedData;
  make_string u.public_data p ulPublicDataLen pPublicData;
  setf p ulPrivateDataLen u.private_data_len;
  setf p hPrivateData u.private_data;
  make_string u.public_data2 p ulPublicDataLen2 pPublicData2;
  setf p publicKey u.public_key;
  p

let view p =
  { kdf = Pkcs11_CK_EC_KDF_TYPE.view @@ getf p kdf
  ; shared_data = view_string_option p ulSharedDataLen pSharedData
  ; public_data = view_string p ulPublicDataLen pPublicData
  ; private_data_len = getf p ulPrivateDataLen
  ; private_data = getf p hPrivateData
  ; public_data2 = view_string p ulPublicDataLen2 pPublicData2
  ; public_key = getf p publicKey
  }

let compare : u -> u -> int =
  Pervasives.compare

let u_to_yojson u =
  `Assoc
    [ "kdf", Pkcs11_CK_EC_KDF_TYPE.u_to_yojson u.kdf
    ; "shared_data", [%to_yojson: string option] u.shared_data
    ; "public_data", `String u.public_data
    ; "private_data_len", `String (Unsigned.ULong.to_string u.private_data_len)
    ; "private_data", `String (Unsigned.ULong.to_string u.private_data)
    ; "public_data2", `String u.public_data2
    ; "public_key", `String (Unsigned.ULong.to_string u.public_key)
    ]
