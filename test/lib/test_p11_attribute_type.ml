open OUnit2

let compare_suite =
  let test ~a ~b ~expected ctxt =
    let actual = P11_attribute_type.compare a b in
    assert_equal ~ctxt ~printer:[%show: int] expected actual
  in
  [ "equal" >::
    test
      ~a:P11_attribute_type.CKA_EXTRACTABLE
      ~b:P11_attribute_type.CKA_EXTRACTABLE
      ~expected:0
  ]

let compare'_suite =
  let test ~a ~b ~expected ctxt =
    let actual = P11_attribute_type.compare' a b in
    assert_equal ~ctxt expected actual
  in
  [ "equal" >::
    test
      ~a:P11_attribute_type.CKA_EXTRACTABLE
      ~b:P11_attribute_type.CKA_EXTRACTABLE
      ~expected:P11_attribute_type.Equal
  ; "equal with unknown" >::
    ( fun _ctxt ->
        let open P11_attribute_type in
        match compare' CKA_MODIFIABLE (CKA_CS_UNKNOWN Encoding._CKA_MODIFIABLE) with
        | _ -> assert_failure "Comparing with unknown attribute type should raise"
        | exception Assert_failure ("lib/p11_attribute_type.ml", _, _) -> ()
    )
  ; "not equal" >::
    test
      ~a:P11_attribute_type.CKA_MODIFIABLE
      ~b:P11_attribute_type.CKA_EXTRACTABLE
      ~expected:(P11_attribute_type.Not_equal 1)
  ; "not equal with unknown" >::
    test
      ~a:P11_attribute_type.CKA_MODIFIABLE
      ~b:(P11_attribute_type.CKA_CS_UNKNOWN P11_attribute_type.Encoding._CKA_EXTRACTABLE)
      ~expected:(P11_attribute_type.Not_equal 1)
  ]

let suite =
  "P11_attribute_type" >:::
  [ "compare" >::: compare_suite
  ; "compare'" >::: compare'_suite
  ]
