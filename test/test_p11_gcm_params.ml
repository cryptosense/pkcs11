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
  "make" >:: fun ctxt ->
    let iv = "iv" in
    let aad = "aad" in
    let tag_bits = Unsigned.ULong.of_int 16 in
    let params = P11_gcm_params.make ~iv ~aad ~tag_bits in
    let expected = (iv, aad, tag_bits) in
    let got =
      ( P11_gcm_params.iv params
      , P11_gcm_params.aad params
      , P11_gcm_params.tag_bits params
      )
    in
    assert_equal
      ~ctxt
      ~cmp:[%eq: string * string * P11_ulong.t]
      ~printer:[%show: string * string * P11_ulong.t]
      expected
      got

let test_of_yojson =
  "of_yojson" >:: fun ctxt ->
    let iv = "iv" in
    let aad = "aad" in
    let tag_bits = Unsigned.ULong.of_int 16 in
    let json =
      `Assoc
        [ "iv", `String iv
        ; "aad", `String aad
        ; "tag_bits", `String "16"
        ]
    in
    let expected = Ok (P11_gcm_params.make ~iv ~aad ~tag_bits) in
    let got = P11_gcm_params.of_yojson json in
    assert_equal
      ~ctxt
      ~cmp:[%eq: (P11_gcm_params.t, string) Result.result]
      ~printer:[%show: (P11_gcm_params.t, string) Result.result]
      expected
      got

let test_to_yojson =
  "to_yojson" >:: fun ctxt ->
    let iv = "iv" in
    let aad = "aad" in
    let tag_bits = Unsigned.ULong.of_int 16 in
    let expected =
      `Assoc
        [ "iv", `String iv
        ; "aad", `String aad
        ; "tag_bits", `String "16"
        ]
    in
    let params = P11_gcm_params.make ~iv ~aad ~tag_bits in
    let got = P11_gcm_params.to_yojson params in
    assert_equal
      ~ctxt
      ~cmp:[%eq: yojson]
      ~printer:[%show: yojson]
      expected
      got

let suite =
  "GCM_params" >:::
  [ test_make
  ; test_of_yojson
  ; test_to_yojson
  ]
