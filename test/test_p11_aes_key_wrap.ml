open OUnit2


type yojson =
  [ `Null
  | `Bool of bool
  | `Int of int
  | `Float of float
  | `String of string
  | `Intlit of string
  | `List of yojson list
  | `Tuple of yojson list
  | `Assoc of (string * yojson) list
  | `Variant of (string * yojson option)
  ]
[@@deriving eq,show]


let test_to_yojson =
  let test params expected ctxt =
    let got = P11_aes_key_wrap_params.to_yojson params in
    assert_equal
      ~ctxt
      ~cmp:[%eq: yojson]
      ~printer:[%show: yojson]
      expected
      got
  in
  "to_yojson" >:::
  [ "default" >:: test
    P11_aes_key_wrap_params.default
    `Null
  ; "explicit" >:: test
    (P11_aes_key_wrap_params.explicit "AAAABBBBCCCCDDDD")
    (`String "0x41414141424242424343434344444444")
  ]


let test_explicit_iv =
  let test params expected ctxt =
    let got = P11_aes_key_wrap_params.explicit_iv params in
    assert_equal
      ~ctxt
      ~cmp:[%eq: string option]
      ~printer:[%show: string option]
      expected
      got
  in
  let iv = "12345678" in
  "explicit_iv" >:::
  [ "Default" >:: test
      P11_aes_key_wrap_params.default
      None
  ; "Explicit" >:: test
      (P11_aes_key_wrap_params.explicit iv)
      (Some iv)
  ]


let suite =
  "P11_aes_key_wrap" >:::
  [ test_to_yojson
  ; test_explicit_iv
  ]
