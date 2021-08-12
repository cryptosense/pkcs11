open Ctypes

type _t

type t =
  { length : P11_ulong.t ptr
  ; mutable content : Pkcs11_CK_SLOT_ID.t ptr }

type u = Pkcs11_CK_SLOT_ID.t list

let get_length (t : t) : P11_ulong.t = !@(t.length)

let get_content (t : t) : Pkcs11_CK_SLOT_ID.t ptr = t.content

let get_length_addr (t : t) : P11_ulong.t ptr = t.length

let create () : t =
  { length = Ctypes.allocate ulong Unsigned.ULong.zero
  ; content = from_voidp Pkcs11_CK_SLOT_ID.typ null }

let allocate (t : t) : unit =
  let n = get_length t |> Unsigned.ULong.to_int in
  let data = allocate_n Pkcs11_CK_SLOT_ID.typ ~count:n in
  t.content <- data;
  ()

let view (t : t) : u =
  let length = get_length t |> Unsigned.ULong.to_int in
  let array = CArray.from_ptr (get_content t) length in
  CArray.to_list array

let make (u : u) : t =
  let array = CArray.of_list ulong u in
  { length = Ctypes.allocate ulong (Unsigned.ULong.of_int (List.length u))
  ; content = CArray.start array }
