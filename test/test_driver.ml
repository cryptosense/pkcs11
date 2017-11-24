open OUnit2

let suite =
  "Functional" >:::
  [ Test_p11_load.suite
  ]

let () = run_test_tt_main suite
