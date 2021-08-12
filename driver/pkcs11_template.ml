open Ctypes

type t = Pkcs11_CK_ATTRIBUTE.t Ctypes.carray

let of_list l = Ctypes.CArray.of_list Pkcs11_CK_ATTRIBUTE.ck_attribute l

(** [allocate t]: given a template (an array of attribute with
values set to NULL) this function allocates memory for the content
of each attribute. *)
let allocate t =
  let open Ctypes in
  for i = 0 to CArray.length t - 1 do
    Pkcs11_CK_ATTRIBUTE.allocate (CArray.get t i)
  done;
  ()

let to_list (t : t) = Ctypes.CArray.to_list t

let view t = Ctypes.CArray.to_list t |> List.map Pkcs11_CK_ATTRIBUTE.view

let make u : t =
  List.map Pkcs11_CK_ATTRIBUTE.make_pack u
  |> CArray.of_list Pkcs11_CK_ATTRIBUTE.ck_attribute
