type s

type t = s Ctypes.structure

let t : t Ctypes.typ = Ctypes.structure "CK_AES_CTR_PARAMS"

let bits = Ctypes_helpers.smart_field t "bits" Ctypes.ulong

let block = Ctypes_helpers.smart_field t "block" (Ctypes.array 16 Ctypes.char)

let () = Ctypes.seal t

let make u =
  let p = Ctypes.make t in
  Ctypes.setf p bits @@ P11_aes_ctr_params.bits u;
  Ctypes.setf p block
  @@ Ctypes_helpers.carray_from_string
  @@ P11_aes_ctr_params.block u;
  p

let view p =
  let bits = Ctypes.getf p bits in
  let block = Ctypes_helpers.string_from_carray @@ Ctypes.getf p block in
  P11_aes_ctr_params.make ~bits ~block
