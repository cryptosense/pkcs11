open OUnit2

let suite =
  "Pkcs11" >:::
  [ Test_bigint.suite
  ; Test_p11_attribute.suite
  ; Test_p11_attribute_type.suite
  ; Test_template.suite
  ; Test_p11_aes_ctr_params.suite
  ]

let () = run_test_tt_main suite
