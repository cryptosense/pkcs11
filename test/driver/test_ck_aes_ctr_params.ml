open OUnit2

let test_make =
  "make" >:: fun ctxt ->
  let bits = Unsigned.ULong.of_int 16 in
  let block = "AAAABBBBCCCCDDDD" in
  let high_level = P11.AES_CTR_params.make ~bits ~block in
  let low_level = Pkcs11_CK_AES_CTR_PARAMS.make high_level in
  let expected = (bits, block) in
  let got_bits = Ctypes.getf low_level Pkcs11_CK_AES_CTR_PARAMS.bits in
  let got_block =
    Ctypes_helpers.string_from_carray
      (Ctypes.getf low_level Pkcs11_CK_AES_CTR_PARAMS.block)
  in
  let got = (got_bits, got_block) in
  assert_equal ~ctxt ~cmp:[%eq: P11_ulong.t * string]
    ~printer:[%show: P11_ulong.t * string] expected got

let test_view =
  let test low_level expected ctxt =
    let got = Pkcs11_CK_AES_CTR_PARAMS.view low_level in
    assert_equal ~ctxt ~cmp:[%eq: P11_aes_ctr_params.t]
      ~printer:[%show: P11_aes_ctr_params.t] expected got
  in
  let build ~bits ~block =
    let p = Ctypes.make Pkcs11_CK_AES_CTR_PARAMS.t in
    Ctypes.setf p Pkcs11_CK_AES_CTR_PARAMS.bits bits;
    Ctypes.setf p Pkcs11_CK_AES_CTR_PARAMS.block block;
    p
  in
  let bits = Unsigned.ULong.of_int 16 in
  let block = "AAAABBBBCCCCDDDD" in
  "view"
  >::: [ "Ok"
         >:: test
               (build ~bits ~block:(Ctypes_helpers.carray_from_string block))
               (P11_aes_ctr_params.make ~bits ~block) ]

let suite = "CK_AES_CTR_PARAMS" >::: [test_make; test_view]
