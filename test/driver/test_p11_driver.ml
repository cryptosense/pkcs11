open OUnit2

type get_attribute_value_params =
  P11.Session_handle.t * P11.Object_handle.t * P11.Attribute_types.t
[@@deriving eq, show]

module type Mock_driver_params = sig
  val c_GetAttributeValue :
       Pkcs11.CK_SESSION_HANDLE.t
    -> Pkcs11.CK_OBJECT_HANDLE.t
    -> Pkcs11.CK_ATTRIBUTE.t Ctypes.ptr
    -> Pkcs11.CK_ULONG.t
    -> Pkcs11.CK_RV.t
end

module type Mock_low_level_bindings = sig
  include Pkcs11.LOW_LEVEL_BINDINGS

  val get_attribute_value_calls : get_attribute_value_params list ref
end

module Mock_low_level_bindings (M : Mock_driver_params) :
  Mock_low_level_bindings = struct
  include Pkcs11.Fake ()

  let get_attribute_value_calls = ref []

  let c_GetAttributeValue session_handle object_handle template count =
    let attributes =
      let num_items = Unsigned.ULong.to_int count in
      Pkcs11.Template.to_list (Ctypes.CArray.from_ptr template num_items)
      |> List.map Pkcs11.CK_ATTRIBUTE.get_type
      |> List.map Pkcs11.CK_ATTRIBUTE_TYPE.view
    in
    get_attribute_value_calls :=
      (session_handle, object_handle, attributes) :: !get_attribute_value_calls;
    M.c_GetAttributeValue session_handle object_handle template count
end

module type Mock_driver = sig
  include P11_driver.S

  val get_attribute_value_calls : get_attribute_value_params list ref
end

module Mock_driver (M : Mock_driver_params) = struct
  module MDR : Mock_low_level_bindings = Mock_low_level_bindings (M)

  include P11_driver.Wrap_low_level_bindings (MDR)

  let get_attribute_value_calls = MDR.get_attribute_value_calls
end

let mock_driver (module M : Mock_driver_params) () =
  (module Mock_driver (M) : Mock_driver)

module Fixtures = struct
  let session_handle = Unsigned.ULong.zero

  let object_handle = Unsigned.ULong.zero
end

let test_get_attribute_value_optimized =
  let open Fixtures in
  let test ~attributes ~f ~expected_calls ctxt =
    let params =
      (module struct
        let c_GetAttributeValue = f
      end : Mock_driver_params)
    in
    let driver = mock_driver params () in
    let (module Driver : Mock_driver) = driver in
    let (`Optimized get) =
      P11_driver.get_attribute_value_optimized (module (val driver)) attributes
    in
    (* Get the values twice to trigger optimization behaviour *)
    let _ = get session_handle object_handle in
    let _ = get session_handle object_handle in
    let actual_calls = List.rev !Driver.get_attribute_value_calls in
    assert_equal ~ctxt ~cmp:[%eq: get_attribute_value_params list]
      ~printer:[%show: get_attribute_value_params list] expected_calls
      actual_calls
  in
  "get_attribute_value_optimized"
  >::: [ "Always failing implies single gets"
         >:: test
               ~attributes:P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP]
               ~f:(fun _ _ _ _ -> Pkcs11.CK_RV.make P11.RV.CKR_GENERAL_ERROR)
               ~expected_calls:
                 (* The first time, a group attempt will be made, and then we fall back to single elements *)
                 [ ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP] )
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP] )
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_UNWRAP] )
                   (* The second time, we will have marked both elements as bad, so we query an empty group
                      and fall back to single elements. *)
                 ; (session_handle, object_handle, [])
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP] )
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_UNWRAP] ) ]
       ; "Initial success implies bulk gets"
         >:: test
               ~attributes:P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP]
               ~f:(fun _ _ _ _ -> Pkcs11.CK_RV.make P11.RV.CKR_OK)
               ~expected_calls:
                 (* The first time, since the request succeeds it is made twice (once with memory allocated
                    and once without) see p11_driver.ml for the code that does this. *)
                 [ ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP] )
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP] )
                   (* The same thing happens the second time as both are marked as good. *)
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP] )
                 ; ( session_handle
                   , object_handle
                   , P11.Attribute_type.[Pack CKA_WRAP; Pack CKA_UNWRAP] ) ] ]

let suite = "P11_driver" >::: [test_get_attribute_value_optimized]
