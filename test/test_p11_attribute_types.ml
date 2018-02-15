open OUnit2

let test_mem =
  let test attribute_types query expected ctxt =
    let got = P11_attribute_types.mem attribute_types query in
    assert_equal
      ~ctxt
      ~cmp:[%eq: bool]
      ~printer:[%show: bool]
      expected
      got
  in
  let open P11_attribute_type in
  "mem" >:::
  [ "not in list" >:: test
      [Pack CKA_WRAP]
      CKA_ENCRYPT
      false
  ; "in list" >:: test
      [ Pack CKA_WRAP
      ; Pack CKA_ENCRYPT
      ; Pack CKA_TOKEN
      ]
      CKA_ENCRYPT
      true
  ]

let suite =
  "P11_attribute_types" >:::
  [ test_mem
  ]
