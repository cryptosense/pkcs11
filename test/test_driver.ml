open OUnit2

let assert_equal_object_handle ~ctxt =
  assert_equal
    ~ctxt
    ~cmp:[%eq: P11.Object_handle.t]
    ~printer:[%show: P11.Object_handle.t]

let assert_equal_string ~ctxt =
  assert_equal
    ~ctxt
    ~cmp:[%eq: string]
    ~printer:[%show: string]

let test_get_info (module R : P11_driver.S) ctxt =
  let open P11.Info in
  let open P11.Version in
  let got = R.get_info () in
  let expected =
    { cryptokiVersion =
        { major = 1
        ; minor = 2
        }
    ; libraryVersion =
        { major = 3
        ; minor = 4
        }
    ; manufacturerID = "fake manufacturer ID\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ; libraryDescription = "fake library description\x00\x00\x00\x00\x00\x00\x00\x00"
    ; flags = Unsigned.ULong.of_int 5
    }
  in
  assert_equal
    ~ctxt
    ~cmp:[%eq: P11.Info.t]
    ~printer:[%show: P11.Info.t]
    expected
    got

let test_get_slot_list (module R : P11_driver.S) ctxt =
  let expected_slots = [Unsigned.ULong.zero] in
  let got_slots = R.get_slot_list true in
  assert_equal
    ~ctxt
    ~cmp:[%eq: P11.Slot_id.t list]
    ~printer:[%show: P11.Slot_id.t list]
    expected_slots
    got_slots

let test_encrypt (module R : P11_driver.S) session key ctxt =
  let plaintext = "YELLOW SUBMARINE" in
  let got = R.encrypt session P11.Mechanism.CKM_AES_ECB key plaintext in
  let expected = "fake ciphertext" in
  assert_equal_string ~ctxt expected got

let test_decrypt (module R : P11_driver.S) session key ctxt =
  let ciphertext = "ICE ICE ICE BABY" in
  let got = R.decrypt session P11.Mechanism.CKM_AES_ECB key ciphertext in
  let expected = "fake recovered" in
  assert_equal_string ~ctxt expected got

let test_create_object (module R : P11_driver.S) session ctxt =
  let expected = Unsigned.ULong.of_int 1 in
  let got = R.create_object session [] in
  assert_equal_object_handle ~ctxt expected got

let test_copy_object (module R : P11_driver.S) session key ctxt =
  let expected = Unsigned.ULong.of_int 1 in
  let got = R.copy_object session key [] in
  assert_equal_object_handle ~ctxt expected got

let test_get_attribute_value (module R : P11_driver.S) session key =
  let test attribute_type value ctxt =
    let pack_type = P11.Attribute_type.Pack attribute_type in
    let template = R.get_attribute_value session key [pack_type] in
    let expected = Some (P11.Attribute.Pack (attribute_type, value)) in
    let got = P11.Template.get_pack template pack_type in
    assert_equal
      ~ctxt
      ~cmp:[%eq: P11.Attribute.pack option]
      ~printer:[%show: P11.Attribute.pack option]
      expected
      got
  in
  [ "CKA_CLASS" >:: test P11.Attribute_type.CKA_CLASS P11.Object_class.CKO_SECRET_KEY
  ; "CKA_TOKEN" >:: test P11.Attribute_type.CKA_TOKEN false
  ; "CKA_WRAP" >:: test P11.Attribute_type.CKA_WRAP true
  ; "CKA_UNWRAP" >:: test P11.Attribute_type.CKA_UNWRAP true
  ; "CKA_VALUE" >:: test P11.Attribute_type.CKA_VALUE
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  ; "CKA_VALUE_LEN" >:: test P11.Attribute_type.CKA_VALUE_LEN (Unsigned.ULong.of_int 16)
  ; "CKA_KEY_TYPE" >:: test P11.Attribute_type.CKA_KEY_TYPE P11.Key_type.CKK_AES
  ; "CKA_ENCRYPT" >:: test P11.Attribute_type.CKA_ENCRYPT true
  ; "CKA_DECRYPT" >:: test P11.Attribute_type.CKA_DECRYPT true
  ; "CKA_SIGN" >:: test P11.Attribute_type.CKA_SIGN true
  ; "CKA_VERIFY" >:: test P11.Attribute_type.CKA_VERIFY true
  ; "CKA_MODULUS" >:: test P11.Attribute_type.CKA_MODULUS
      (P11.Bigint.decode
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
  ; "CKA_PUBLIC_EXPONENT" >:: test P11.Attribute_type.CKA_PUBLIC_EXPONENT (P11.Bigint.of_int 65537)
  ]

let test_set_attribute_value (module R : P11_driver.S) session key ctxt =
  R.set_attribute_value session key []

let test_generate_key_pair (module R : P11_driver.S) session ctxt =
  let (pub, priv) = R.generate_key_pair session P11.Mechanism.CKM_AES_KEY_GEN [] [] in
  assert_equal_object_handle ~ctxt (Unsigned.ULong.of_int 1) pub;
  assert_equal_object_handle ~ctxt (Unsigned.ULong.of_int 2) priv

let test_derive (module R : P11_driver.S) session key ctxt =
  let mechanism = P11.Mechanism.CKM_XOR_BASE_AND_DATA "test" in
  let template = [] in
  let expected = Unsigned.ULong.of_int 1 in
  let got = R.derive_key session mechanism key template in
  assert_equal_object_handle ~ctxt expected got

let test_sign (module R : P11_driver.S) session key ctxt =
  let plaintext = "some data" in
  let mechanism = P11.Mechanism.CKM_SHA256_RSA_PKCS in
  let got = R.sign session mechanism key plaintext in
  let expected = "fake signature" in
  assert_equal_string ~ctxt expected got

let test_verify (module R : P11_driver.S) session key =
  let verify signature =
    let mechanism = P11.Mechanism.CKM_SHA256_RSA_PKCS in
    let data = "some data" in
    R.verify session mechanism key ~data ~signature
  in
  let test_valid ctxt =
    assert_equal
      ~ctxt
      ()
      (verify "OK")
  in
  let test_invalid ctxt =
    assert_raises (P11_driver.CKR P11.RV.CKR_SIGNATURE_INVALID) @@ fun () ->
    verify "Invalid"
  in
  [ "Valid" >:: test_valid
  ; "Invalid" >:: test_invalid
  ]

let test_wrap (module R : P11_driver.S) session key ctxt =
  let mechanism = P11.Mechanism.CKM_AES_ECB in
  let expected = "fake wrapped" in
  let got = R.wrap_key session mechanism key key in
  assert_equal_string ~ctxt expected got

let test_unwrap (module R : P11_driver.S) session key ctxt =
  let mechanism = P11.Mechanism.CKM_AES_ECB in
  let expected = Unsigned.ULong.of_int 1 in
  let plaintext = "plaintext" in
  let got = R.unwrap_key session mechanism key plaintext [] in
  assert_equal_object_handle ~ctxt expected got

let test_driver driver =
  [ "Get info" >:: test_get_info driver
  ; "Get slot list" >:: test_get_slot_list driver
  ]

let open_session (module R : P11_driver.S) =
  let session =
    R.open_session
      ~slot:Unsigned.ULong.zero
      ~flags:P11.Flags._CKF_SERIAL_SESSION
  in
  R.login session P11.User_type.CKU_USER "1234";
  session

let test_session driver =
  let session = open_session driver in
  [ "Create object" >:: test_create_object driver session
  ; "Generate key pair" >:: test_generate_key_pair driver session
  ]

let test_object driver =
  let session = open_session driver in
  let (module R : P11_driver.S) = driver in
  let key =
    R.generate_key
      session
      P11.Mechanism.CKM_AES_KEY_GEN
      [ P11.Attribute.Pack (
            P11.Attribute_type.CKA_VALUE_LEN,
            Unsigned.ULong.of_int 32
          )
      ]
  in
  [ "Encrypt" >:: test_encrypt driver session key
  ; "Decrypt" >:: test_decrypt driver session key
  ; "Copy object" >:: test_copy_object driver session key
  ; "Get attribute value" >::: test_get_attribute_value driver session key
  ; "Set attribute value" >:: test_set_attribute_value driver session key
  ; "Derive" >:: test_derive driver session key
  ; "Sign" >:: test_sign driver session key
  ; "Verify" >::: test_verify driver session key
  ; "Wrap" >:: test_wrap driver session key
  ; "Unwrap" >:: test_unwrap driver session key
  ]

let test_p11_load =
  let dll = "./_build/src_dll/dllpkcs11_fake.so" in
  let driver =
    P11_driver.load_driver
      ?log_calls:None
      ?on_unknown:None
      ~use_get_function_list:`False
      ~dll
  in
  let (module R) = driver in
  R.initialize ();
  [ "Driver" >::: test_driver driver
  ; "Session" >::: test_session driver
  ; "Object" >::: test_object driver
  ]

let suite =
  "Functional" >:::
  [ "Load P11" >::: test_p11_load
  ]

let () = run_test_tt_main suite
