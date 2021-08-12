type t = P11_ulong.t

let view_error n = Pkcs11_log.log @@ Printf.sprintf "Unknown CKU code: 0x%Lx" n

let typ = Ctypes.ulong

let _CKU_SO = Unsigned.ULong.of_string (Int64.to_string 0L)

let _CKU_USER = Unsigned.ULong.of_string (Int64.to_string 1L)

let _CKU_CONTEXT_SPECIFIC = Unsigned.ULong.of_string (Int64.to_string 2L)

let make u =
  let open P11_user_type in
  match u with
  | CKU_SO -> _CKU_SO
  | CKU_USER -> _CKU_USER
  | CKU_CONTEXT_SPECIFIC -> _CKU_CONTEXT_SPECIFIC
  | CKU_CS_UNKNOWN x -> x

let view t =
  let open P11_user_type in
  let is value = Unsigned.ULong.compare t value = 0 in
  match () with
  | _ when is _CKU_SO -> CKU_SO
  | _ when is _CKU_USER -> CKU_USER
  | _ when is _CKU_CONTEXT_SPECIFIC -> CKU_CONTEXT_SPECIFIC
  | _ ->
    view_error (Int64.of_string (Unsigned.ULong.to_string t));
    CKU_CS_UNKNOWN t
