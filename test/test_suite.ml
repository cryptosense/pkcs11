open OUnit2

let suite =
  "Pkcs11" >:::
  [ Test_bigint.suite
  ; Test_p11_attribute_type.suite
  ; Test_template.suite
  ]

let () = run_test_tt_main suite
