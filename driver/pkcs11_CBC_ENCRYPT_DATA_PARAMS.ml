(** Helper to define [CK_*_CBC_ENCRYPT_DATA_PARAMS] *)

open Ctypes
open Ctypes_helpers

module type HIGHER = sig
  type t =
    { iv : string
    ; data : string }
  [@@deriving ord, yojson]
end

module type PARAM = sig
  val name : string

  val size : int
end

module Make (Param : PARAM) (Higher : HIGHER) = struct
  type _t

  type t = _t structure

  let t : t typ = structure Param.name

  let iv_size = Param.size

  let ( -: ) typ label = smart_field t label typ

  let iv = array iv_size Pkcs11_CK_BYTE.typ -: "iv"

  let pData = Reachable_ptr.typ Pkcs11_CK_BYTE.typ -: "pData"

  let length = ulong -: "length"

  let () = seal t

  let make u =
    let open Higher in
    let t = make t in
    (* Build the variable length string *)
    make_string u.data t length pData;

    (* Copy the fixed length string *)
    if String.length u.iv <> iv_size then
      invalid_arg "CBC_ENCRYPT_DATA_PARAMS: invalid IV size.";
    string_copy u.iv iv_size (CArray.start (getf t iv));
    t

  let view t =
    let open Higher in
    { iv = string_from_carray (getf t iv)
    ; data =
        string_from_ptr
          ~length:(getf t length |> Unsigned.ULong.to_int)
          (Reachable_ptr.getf t pData) }
end

module CK_DES_CBC_ENCRYPT_DATA_PARAMS =
  Make
    (struct
      let name = "CK_DES_CBC_ENCRYPT_DATA_PARAMS"

      let size = 8
    end)
    (P11_des_cbc_encrypt_data_params)

module CK_AES_CBC_ENCRYPT_DATA_PARAMS =
  Make
    (struct
      let name = "CK_AES_CBC_ENCRYPT_DATA_PARAMS"

      let size = 16
    end)
    (P11_aes_cbc_encrypt_data_params)
