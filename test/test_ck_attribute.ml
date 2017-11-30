open OUnit2

let test_view =
  let test low expected ctxt =
    let got = Pkcs11_CK_ATTRIBUTE.view low in
    assert_equal
      ~ctxt
      ~cmp:[%eq: P11_attribute.pack]
      ~printer:[%show: P11_attribute.pack]
      expected
      got
  in
  let object_class = P11_object_class.CKO_SECRET_KEY in
  let key_type = P11_key_type.CKK_AES in
  let bool = true in
  let string = "string" in
  let bigint = P11_bigint.zero in
  let ulong = Unsigned.ULong.zero in
  let key_gen_mechanism = P11_key_gen_mechanism.CK_UNAVAILABLE_INFORMATION in
  let unknown_ckm = Unsigned.ULong.of_int 0x5555 in
  "view" >:::
  [ "object_class" >:: test
      (Pkcs11_CK_ATTRIBUTE.ulong
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CLASS
         (Pkcs11_CK_OBJECT_CLASS.make object_class)
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_CLASS, object_class)
      )
  ; "bool" >:: test
      (Pkcs11_CK_ATTRIBUTE.boolean
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TOKEN
         bool
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_TOKEN, bool)
      )
  ; "string" >:: test
      (Pkcs11_CK_ATTRIBUTE.string
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_LABEL
         string
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_LABEL, string)
      )
  ; "not implemented" >:: test
      (Pkcs11_CK_ATTRIBUTE.string
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHECK_VALUE
         string
      )
      (P11_attribute.Pack
         ( P11_attribute_type.CKA_CHECK_VALUE
         , P11_attribute_type.NOT_IMPLEMENTED string
         )
      )
  ; "key_type" >:: test
      (Pkcs11_CK_ATTRIBUTE.ulong
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_TYPE
         (Pkcs11_CK_KEY_TYPE.make key_type)
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_KEY_TYPE, key_type)
      )
  ; "bigint" >:: test
      (Pkcs11_CK_ATTRIBUTE.bigint
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS
         bigint
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_MODULUS, bigint)
      )
  ; "ulong" >:: test
      (Pkcs11_CK_ATTRIBUTE.ulong
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS_BITS
         ulong
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_MODULUS_BITS, ulong)
      )
  ; "key_gen_mechanism" >:: test
      (Pkcs11_CK_ATTRIBUTE.ulong
         Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_GEN_MECHANISM
         (Pkcs11_key_gen_mechanism.make key_gen_mechanism)
      )
      (P11_attribute.Pack
         (P11_attribute_type.CKA_KEY_GEN_MECHANISM, key_gen_mechanism)
      )
  ; "unknown" >:: test
      (Pkcs11_CK_ATTRIBUTE.string
         unknown_ckm
         string
      )
      (P11_attribute.Pack
         ( P11_attribute_type.CKA_CS_UNKNOWN unknown_ckm
         , P11_attribute_type.NOT_IMPLEMENTED string
         )
      )
  ]

let suite =
  "CK_ATTRIBUTE" >:::
  [ test_view
  ]
