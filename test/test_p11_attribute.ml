open OUnit2

let pack_to_yojson_suite =
  let test ~pack ~expected ctxt =
    let actual = P11_attribute.pack_to_yojson pack in
    assert_equal
      ~ctxt
      ~printer:[%show: string]
      (Yojson.Safe.to_string expected)
      (Yojson.Safe.to_string actual)
  in
  [ "CKA_EC_PARAMS" >::
    test
      ~pack:(P11_attribute.Pack (P11_attribute_type.CKA_EC_PARAMS, "\x00"))
      ~expected:(`Assoc [("CKA_EC_PARAMS", `String "0x00")])
  ]

let pack_of_yojson_suite =
  let test ~json ~expected ctxt =
    let actual = P11_attribute.pack_of_yojson json in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (P11_attribute.pack, string) Result.result]
      ~printer:[%show: (P11_attribute.pack, string) Result.result]
      expected
      actual
  in
  [ "CKA_EC_PARAMS" >::
    test
      ~json:(`Assoc [("CKA_EC_PARAMS", `String "0x00")])
      ~expected:(Ok (P11_attribute.Pack (P11_attribute_type.CKA_EC_PARAMS, "\x00")))
  ]

let suite =
  "P11_attribute" >:::
  [ "pack_of_yojson" >::: pack_of_yojson_suite
  ; "pack_to_yojson" >::: pack_to_yojson_suite
  ]
