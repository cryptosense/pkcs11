open OUnit2

let suite =
  "Pkcs11" >:::
  [ Test_p11_aes_ctr_params.suite
  ; Test_p11_aes_key_wrap.suite
  ; Test_p11_attribute.suite
  ; Test_p11_attribute_type.suite
  ; Test_p11_attribute_types.suite
  ; Test_p11_gcm_params.suite
  ; Test_p11_hex_data.suite
  ; Test_p11_mechanism.suite
  ; Test_template.suite
  ; Test_bigint.suite
  ]

let () = run_test_tt_main suite
