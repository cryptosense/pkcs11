open OUnit2

let pack_to_yojson_suite =
  let test attr value expected ctxt =
    let pack = P11_attribute.Pack (attr, value) in
    let actual = P11_attribute.pack_to_yojson pack in
    assert_equal ~ctxt ~printer:[%show: string]
      (Yojson.Safe.to_string expected)
      (Yojson.Safe.to_string actual)
  in
  let assoc k v = `Assoc [(k, `String v)] in
  [ "CKA_EC_PARAMS"
    >:: test P11_attribute_type.CKA_EC_PARAMS "\x00"
          (assoc "CKA_EC_PARAMS" "0x00")
  ; "CKA_ID" >:: test P11_attribute_type.CKA_ID "\x00" (assoc "CKA_ID" "0x00")
  ; "CKA_CLASS"
    >:: test P11_attribute_type.CKA_CLASS P11_object_class.CKO_PRIVATE_KEY
          (assoc "CKA_CLASS" "CKO_PRIVATE_KEY")
  ; "CKO_TOKEN"
    >:: test P11_attribute_type.CKA_TOKEN true (assoc "CKA_TOKEN" "CK_TRUE")
  ; "CKA_LABEL"
    >:: test P11_attribute_type.CKA_LABEL "label" (assoc "CKA_LABEL" "label")
  ; "CKA_KEY_TYPE"
    >:: test P11_attribute_type.CKA_KEY_TYPE P11_key_type.CKK_ARIA
          (assoc "CKA_KEY_TYPE" "CKK_ARIA")
  ; "CKA_START_DATE"
    >:: test P11_attribute_type.CKA_START_DATE (NOT_IMPLEMENTED "ABCD")
          (assoc "CKA_START_DATE" "0x41424344")
  ; "CKA_MODULUS"
    >:: test P11_attribute_type.CKA_MODULUS (P11_bigint.decode "\x01")
          (assoc "CKA_MODULUS" "0x01")
  ; "CKA_MODULUS_BITS"
    >:: test P11_attribute_type.CKA_MODULUS_BITS Unsigned.ULong.zero
          (assoc "CKA_MODULUS_BITS" "0")
  ; "CKA_KEY_GEN_MECHANISM"
    >:: test P11_attribute_type.CKA_KEY_GEN_MECHANISM
          (P11_key_gen_mechanism.CKM P11_mechanism_type.CKM_ACTI_KEY_GEN)
          (assoc "CKA_KEY_GEN_MECHANISM" "CKM_ACTI_KEY_GEN") ]

let pack_of_yojson_suite =
  let test ~json ~expected ctxt =
    let actual = P11_attribute.pack_of_yojson json in
    assert_equal ~ctxt ~cmp:[%eq: (P11_attribute.pack, string) Result.result]
      ~printer:[%show: (P11_attribute.pack, string) Result.result] expected
      actual
  in
  [ "CKA_EC_PARAMS"
    >:: test
          ~json:(`Assoc [("CKA_EC_PARAMS", `String "0x00")])
          ~expected:
            (Ok (P11_attribute.Pack (P11_attribute_type.CKA_EC_PARAMS, "\x00")))
  ; "CKA_ID"
    >:: test
          ~json:(`Assoc [("CKA_ID", `String "0x00")])
          ~expected:(Ok (Pack (CKA_ID, "\x00"))) ]

let test_compare =
  let test x y expected ctxt =
    let got = P11_attribute.compare x y in
    assert_equal ~ctxt ~cmp:[%eq: int] ~printer:[%show: int] expected got
  in
  [ "Class, same"
    >:: test
          (CKA_CLASS, P11_object_class.CKO_DATA)
          (CKA_CLASS, P11_object_class.CKO_DATA)
          0
  ; "Class, different"
    >:: test
          (CKA_CLASS, P11_object_class.CKO_HW_FEATURE)
          (CKA_CLASS, P11_object_class.CKO_DATA)
          1
  ; "Bool, same" >:: test (CKA_ENCRYPT, true) (CKA_ENCRYPT, true) 0
  ; "Bool, different" >:: test (CKA_ENCRYPT, true) (CKA_ENCRYPT, false) 1
  ; "String, same" >:: test (CKA_LABEL, "label") (CKA_LABEL, "label") 0
  ; "String, different" >:: test (CKA_LABEL, "other") (CKA_LABEL, "label") 1
  ; "Key type, same"
    >:: test
          (CKA_KEY_TYPE, P11_key_type.CKK_ACTI)
          (CKA_KEY_TYPE, P11_key_type.CKK_ACTI)
          0
  ; "Key type, different"
    >:: test
          (CKA_KEY_TYPE, P11_key_type.CKK_ACTI)
          (CKA_KEY_TYPE, P11_key_type.CKK_AES)
          1
  ; "Not implemented, same"
    >:: test
          (CKA_CHECK_VALUE, P11_attribute_type.NOT_IMPLEMENTED "value")
          (CKA_CHECK_VALUE, P11_attribute_type.NOT_IMPLEMENTED "value")
          0
  ; "Not implemented, different"
    >:: test
          (CKA_CHECK_VALUE, P11_attribute_type.NOT_IMPLEMENTED "value")
          (CKA_CHECK_VALUE, P11_attribute_type.NOT_IMPLEMENTED "other")
          1
  ; "Bigint, same"
    >:: test
          (CKA_MODULUS, P11_bigint.decode "xx")
          (CKA_MODULUS, P11_bigint.decode "xx")
          0
  ; "Bigint, different"
    >:: test
          (CKA_MODULUS, P11_bigint.decode "yy")
          (CKA_MODULUS, P11_bigint.decode "xx")
          1
  ; "ULong, same"
    >:: test
          (CKA_MODULUS_BITS, Unsigned.ULong.zero)
          (CKA_MODULUS_BITS, Unsigned.ULong.zero)
          0
  ; "ULong, different"
    >:: test
          (CKA_MODULUS_BITS, Unsigned.ULong.one)
          (CKA_MODULUS_BITS, Unsigned.ULong.zero)
          1
  ; "Key gen mechanism, same"
    >:: test
          (CKA_KEY_GEN_MECHANISM, CKM CKM_AES_KEY_GEN)
          (CKA_KEY_GEN_MECHANISM, CKM CKM_AES_KEY_GEN)
          0
  ; "Key gen mechanism, different"
    >:: test
          ( CKA_KEY_GEN_MECHANISM
          , P11_key_gen_mechanism.CK_UNAVAILABLE_INFORMATION )
          (CKA_KEY_GEN_MECHANISM, CKM CKM_AES_KEY_GEN)
          1
  ; "Data, same" >:: test (CKA_ID, "label") (CKA_ID, "label") 0
  ; "Data, different" >:: test (CKA_ID, "other") (CKA_ID, "label") 1
  ; "Different type"
    >:: test
          (CKA_MODULUS_BITS, Unsigned.ULong.zero)
          (CKA_MODULUS, P11_bigint.decode "xx")
          1
  ; "Same repr, different type" >:: test (CKA_WRAP, true) (CKA_ENCRYPT, true) 1
  ]

let suite =
  "P11_attribute"
  >::: [ "pack_of_yojson" >::: pack_of_yojson_suite
       ; "pack_to_yojson" >::: pack_to_yojson_suite
       ; "compare" >::: test_compare ]
