open OUnit2

module F = struct
  let object_class = P11_object_class.CKO_SECRET_KEY

  let key_type = P11_key_type.CKK_AES

  let bool = true

  let string = "string"

  let bigint = P11_bigint.of_int 65537

  let ulong = Unsigned.ULong.zero

  let key_gen_mechanism = P11_key_gen_mechanism.CK_UNAVAILABLE_INFORMATION

  let unknown_ckm = Unsigned.ULong.of_int 0x5555
end

let test_view =
  let test low expected ctxt =
    let got = Pkcs11_CK_ATTRIBUTE.view low in
    assert_equal ~ctxt ~cmp:[%eq: P11_attribute.pack]
      ~printer:[%show: P11_attribute.pack] expected got
  in
  "view"
  >::: [ "object_class"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CLASS
                  (Pkcs11_CK_OBJECT_CLASS.make F.object_class))
               (P11_attribute.Pack (P11_attribute_type.CKA_CLASS, F.object_class))
       ; "bool"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TOKEN
                  F.bool)
               (P11_attribute.Pack (P11_attribute_type.CKA_TOKEN, F.bool))
       ; "string"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_LABEL
                  F.string)
               (P11_attribute.Pack (P11_attribute_type.CKA_LABEL, F.string))
       ; "not implemented"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.string
                  Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHECK_VALUE F.string)
               (P11_attribute.Pack
                  ( P11_attribute_type.CKA_CHECK_VALUE
                  , P11_attribute_type.NOT_IMPLEMENTED F.string ))
       ; "key_type"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_TYPE
                  (Pkcs11_CK_KEY_TYPE.make F.key_type))
               (P11_attribute.Pack (P11_attribute_type.CKA_KEY_TYPE, F.key_type))
       ; "bigint"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS
                  F.bigint)
               (P11_attribute.Pack (P11_attribute_type.CKA_MODULUS, F.bigint))
       ; "ulong"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.ulong
                  Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS_BITS F.ulong)
               (P11_attribute.Pack (P11_attribute_type.CKA_MODULUS_BITS, F.ulong))
       ; "key_gen_mechanism"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.ulong
                  Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_GEN_MECHANISM
                  (Pkcs11_key_gen_mechanism.make F.key_gen_mechanism))
               (P11_attribute.Pack
                  (P11_attribute_type.CKA_KEY_GEN_MECHANISM, F.key_gen_mechanism))
       ; "unknown"
         >:: test
               (Pkcs11_CK_ATTRIBUTE.string F.unknown_ckm F.string)
               (P11_attribute.Pack
                  ( P11_attribute_type.CKA_CS_UNKNOWN F.unknown_ckm
                  , P11_attribute_type.NOT_IMPLEMENTED F.string )) ]

let test_make =
  let test high expected ctxt =
    let low = Pkcs11_CK_ATTRIBUTE.make high in
    let got_tag = Pkcs11_CK_ATTRIBUTE.get_type low in
    let got_len = Pkcs11_CK_ATTRIBUTE.get_length low in
    let is_null = Pkcs11_CK_ATTRIBUTE.pvalue_is_null_ptr low in
    assert_bool "Pointer should not be NULL" (not is_null);
    let got = (got_tag, got_len) in
    assert_equal ~ctxt ~cmp:[%eq: P11_ulong.t * int]
      ~printer:[%show: P11_ulong.t * int] expected got
  in
  "make"
  >::: [ "object_class"
         >:: test
               (P11.Attribute_type.CKA_CLASS, F.object_class)
               ( Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CLASS
               , Ctypes.sizeof Pkcs11_CK_OBJECT_CLASS.typ )
       ; "bool"
         >:: test
               (P11.Attribute_type.CKA_TOKEN, F.bool)
               ( Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TOKEN
               , Ctypes.sizeof Pkcs11_CK_BBOOL.typ )
       ; "string"
         >:: test
               (P11.Attribute_type.CKA_LABEL, F.string)
               (Pkcs11_CK_ATTRIBUTE_TYPE._CKA_LABEL, String.length F.string)
       ; "not implemented"
         >:: test
               ( P11_attribute_type.CKA_CHECK_VALUE
               , P11_attribute_type.NOT_IMPLEMENTED F.string )
               ( Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHECK_VALUE
               , String.length F.string )
       ; "key_type"
         >:: test
               (P11_attribute_type.CKA_KEY_TYPE, F.key_type)
               ( Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_TYPE
               , Ctypes.sizeof Ctypes.ulong )
       ; "bigint"
         >:: test
               (P11_attribute_type.CKA_MODULUS, F.bigint)
               (Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS, 3)
       ; "ulong"
         >:: test
               (P11_attribute_type.CKA_MODULUS_BITS, F.ulong)
               ( Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS_BITS
               , Ctypes.sizeof Ctypes.ulong )
       ; "key_gen_mechanism"
         >:: test
               (P11_attribute_type.CKA_KEY_GEN_MECHANISM, F.key_gen_mechanism)
               ( Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_GEN_MECHANISM
               , Ctypes.sizeof Ctypes.ulong )
       ; "unknown"
         >:: test
               ( P11_attribute_type.CKA_CS_UNKNOWN F.unknown_ckm
               , P11_attribute_type.NOT_IMPLEMENTED F.string )
               (F.unknown_ckm, String.length F.string) ]

let suite = "CK_ATTRIBUTE" >::: [test_view; test_make]
