(** Helper to define [CK_*_CBC_ENCRYPT_DATA_PARAMS] *)

open Ctypes
open Ctypes_helpers

module type CBC_ENCRYPT_DATA_PARAMS_PARAM =
sig
  val name: string
  val size: int
end

module CBC_ENCRYPT_DATA_PARAMS (Param: CBC_ENCRYPT_DATA_PARAMS_PARAM) =
struct
  type _t
  type t = _t structure
  let t: t typ = structure Param.name

  let iv_size = Param.size

  let (-:) typ label = smart_field t label typ
  let iv = array iv_size Pkcs11_CK_BYTE.typ -: "iv"
  let pData = ptr Pkcs11_CK_BYTE.typ -: "pData"
  let length = ulong -: "length"
  let () = seal t

  type u =
    {
      iv: string;
      data: string;
    }


  let make (u: u): t =
    let t = make t in
    (* Build the variable length string *)
    make_string u.data t length pData;

    (* Copy the fixed length string *)
    if String.length u.iv <> iv_size
    then invalid_arg "CBC_ENCRYPT_DATA_PARAMS: invalid IV size.";
    string_copy u.iv iv_size (CArray.start (getf t iv));
    t

  let view (t: t): u =
    {
      iv = string_from_carray (getf t iv);
      data =
        string_from_ptr
          ~length:(getf t length |> Unsigned.ULong.to_int)
          (getf t pData);
    }

  let compare a b =
    let c = String.compare a.iv b.iv in
    if c <> 0 then
      c
    else
      String.compare a.data b.data
end

module CK_DES_CBC_ENCRYPT_DATA_PARAMS =
  CBC_ENCRYPT_DATA_PARAMS (struct
    let name = "CK_DES_CBC_ENCRYPT_DATA_PARAMS"
    let size = 8
  end)
module CK_AES_CBC_ENCRYPT_DATA_PARAMS =
  CBC_ENCRYPT_DATA_PARAMS (struct
    let name = "CK_AES_CBC_ENCRYPT_DATA_PARAMS"
    let size = 16
  end)
