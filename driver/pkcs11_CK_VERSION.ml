open Ctypes

type _t

type t = _t structure

let ck_version : t typ = structure "CK_VERSION"

let ( -: ) ty label = Ctypes_helpers.smart_field ck_version label ty

let major = Pkcs11_CK_BYTE.typ -: "major"

let minor = Pkcs11_CK_BYTE.typ -: "minor"

let () = seal ck_version

let view c =
  let open P11_version in
  { major = Pkcs11_CK_BYTE.to_int (getf c major)
  ; minor = Pkcs11_CK_BYTE.to_int (getf c minor) }

let make u =
  let open P11_version in
  let t = Ctypes.make ck_version in
  setf t major (Pkcs11_CK_BYTE.of_int u.major);
  setf t minor (Pkcs11_CK_BYTE.of_int u.minor);
  t
