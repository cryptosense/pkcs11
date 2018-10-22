open OUnit2


let test_compare =
  let open P11_mechanism in
  let test a b expected ctxt =
    let got = P11_mechanism.compare a b in
    assert_equal
      ~ctxt
      ~cmp:[%eq: int]
      ~printer:[%show: int]
      expected
      got
  in
  "AES-CTR" >:: test
    (CKM_AES_CTR (P11_aes_ctr_params.make ~bits:(Unsigned.ULong.of_int 1) ~block:""))
    (CKM_AES_CTR (P11_aes_ctr_params.make ~bits:(Unsigned.ULong.of_int 2) ~block:""))
    (-1)


let suite =
  "P11_mechanism" >:::
  [ test_compare
  ]
