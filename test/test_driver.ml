open OUnit2

let suite =
  "Driver" >:::
    [ "Functional" >:::
      [ Test_p11_load.suite
      ]
    ; "Unit" >:::
      [ Test_ck_rv.suite
      ; Test_ck_mechanism_type.suite
      ]
    ]

let () = run_test_tt_main suite
