open OUnit2

let suite =
  "Driver" >:::
    [ "Functional" >:::
      [ Test_p11_load.suite
      ]
    ; "Unit" >:::
      [ Test_ck_rv.suite
      ; Test_ck_mechanism_type.suite
      ; Test_ck_mechanism.suite
      ; Test_ck_attribute.suite
      ; Test_ck_aes_ctr_params.suite
      ; Test_ck_gcm_params.suite
      ; Test_p11_driver.suite
      ]
    ]

let () = run_test_tt_main suite
