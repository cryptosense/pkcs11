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

let test_make =
  let test_ok ~bits ~block ctxt =
    let params = P11_aes_ctr_params.make ~bits ~block in
    let expected = (bits, block) in
    let got = (P11_aes_ctr_params.bits params, P11_aes_ctr_params.block params) in
    assert_equal
      ~ctxt
      ~cmp:[%eq: P11_ulong.t * string]
      ~printer:[%show: P11_ulong.t * string]
      expected
      got
  in
  "make" >:::
  [ "Ok" >:: test_ok
      ~bits:(Unsigned.ULong.of_int 16)
      ~block:"AAAABBBBCCCCDDDD"
  ]

let test_to_yojson =
  let test params expected ctxt =
    let got = P11_aes_ctr_params.to_yojson params in
    assert_equal
      ~ctxt
      ~cmp:[%eq: yojson]
      ~printer:[%show: yojson]
      expected
      got
  in
  "to_yojson" >:::
  [ "normal" >:: test
      ( P11_aes_ctr_params.make
          ~bits:(Unsigned.ULong.of_int 64)
          ~block:"AAAABBBBCCCCDDDD"
      )
      ( `Assoc
          [ ("bits", `String "64")
          ; ("block", `String "0x41414141424242424343434344444444")
          ]
      )
  ]

let test_of_yojson =
  let test json expected ctxt =
    let got = P11_aes_ctr_params.of_yojson json in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (P11_aes_ctr_params.t, string) Result.result]
      ~printer:[%show: (P11_aes_ctr_params.t, string) Result.result]
      expected
      got
  in
  "of_yojson" >:::
  [ "normal" >:: test
      (`Assoc
         [ ("bits", `String "64")
         ; ("block", `String "0x41414141424242424343434344444444")
         ]
      )
      ( Ok
          ( P11_aes_ctr_params.make
              ~bits:(Unsigned.ULong.of_int 64)
              ~block:"AAAABBBBCCCCDDDD"
          )
      )
  ]

let suite =
  "AES_CTR_params" >:::
  [ test_make
  ; test_to_yojson
  ; test_of_yojson
  ]
