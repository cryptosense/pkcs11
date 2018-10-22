open OUnit2

let assert_code_is_known rv =
  let open P11_rv in
  let is_known = match rv with
    | CKR_CS_UNKNOWN _ -> false
    | _ -> true
  in
  assert_bool "Code should be known" is_known

let test_codes_240 =
  let test code _ctxt = 
    let rv = Pkcs11_CK_RV.view @@ Unsigned.ULong.of_int code in
    assert_code_is_known rv
    in
  "2.40 codes" >:::
  [ "CKR_ACTION_PROHIBITED" >:: test 0x0000001b
  ; "CKR_CURVE_NOT_SUPPORTED" >:: test 0x00000140
  ; "CKR_EXCEEDED_MAX_ITERATIONS">:: test 0x000001b5
  ; "CKR_FIPS_SELF_TEST_FAILED">:: test 0x000001b6
  ; "CKR_LIBRARY_LOAD_FAILED" >:: test 0x000001b7
  ; "CKR_PIN_TOO_WEAK">:: test 0x000001b8
  ; "CKR_PUBLIC_KEY_INVALID" >:: test 0x000001b9
  ]

let suite =
  "CK_RV" >:::
    [ test_codes_240
    ]
