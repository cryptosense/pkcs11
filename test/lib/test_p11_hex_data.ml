open OUnit2

let test_of_yojson =
  let test ~data ~expected ctxt = 
    let actual = P11_hex_data.of_yojson data in
    assert_equal ~ctxt
      ~cmp:[%eq: (string, string) result]
      ~printer:[%show: (string, string) result]
      expected
      actual
  in
  "of_yojson" >:::
  [ "not a string" >::
    test
      ~data:`Null
      ~expected:(Error "P11_hex_data: not a string")
  ; "empty" >::
    test
      ~data:(`String "")
      ~expected:(Error "P11_hex_data: string does not start with \"0x\"")
  ; "doesn't start with 0x" >::
    test
      ~data:(`String "00")
      ~expected:(Error "P11_hex_data: string does not start with \"0x\"")
  ; "odd" >::
    test
      ~data:(`String "0x0")
      ~expected:(Error "P11_hex_data: not valid hex-encoded data")
  ; "non-hex characters" >::
    test
      ~data:(`String "0x0g")
      ~expected:(Error "P11_hex_data: not valid hex-encoded data")
  ; "one byte" >::
    test
      ~data:(`String "0x00")
      ~expected:(Ok "\x00")
  ]

let suite =
  "P11_hex_data" >:::
  [ test_of_yojson
  ]
