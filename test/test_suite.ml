open OUnit2

let suite =
  "Pkcs11" >::: [
    Test_template.suite;
    Test_bigint.suite;
  ]

let () = run_test_tt_main suite
