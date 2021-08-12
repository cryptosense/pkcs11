type s

type t = s Ctypes.structure

let t : t Ctypes.typ = Ctypes.structure "CK_GCM_PARAMS"

let pIv =
  Ctypes_helpers.smart_field t "pIv"
    (Ctypes_helpers.Reachable_ptr.typ Pkcs11_CK_BYTE.typ)

let ulIvLen = Ctypes_helpers.smart_field t "ulIvLen" Ctypes.ulong

let ulIvBits = Ctypes_helpers.smart_field t "ulIvBits" Ctypes.ulong

let pAAD =
  Ctypes_helpers.smart_field t "pAAD"
    (Ctypes_helpers.Reachable_ptr.typ Pkcs11_CK_BYTE.typ)

let ulAADLen = Ctypes_helpers.smart_field t "ulAADLen" Ctypes.ulong

let ulTagBits = Ctypes_helpers.smart_field t "ulTagBits" Ctypes.ulong

let () = Ctypes.seal t

let make u =
  let p = Ctypes.make t in
  Ctypes_helpers.make_string (P11_gcm_params.iv u) p ulIvLen pIv;
  Ctypes_helpers.make_string (P11_gcm_params.aad u) p ulAADLen pAAD;
  Ctypes.setf p ulTagBits (P11_gcm_params.tag_bits u);
  p

let view p =
  let iv = Ctypes_helpers.view_string p ulIvLen pIv in
  let aad = Ctypes_helpers.view_string p ulAADLen pAAD in
  let tag_bits = Ctypes.getf p ulTagBits in
  P11_gcm_params.make ~iv ~aad ~tag_bits
