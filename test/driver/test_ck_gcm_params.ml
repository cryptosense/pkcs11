open OUnit2

let test_make =
  "make" >:: fun ctxt ->
    let iv = "iv" in
    let aad = "aad" in
    let tag_bits = Unsigned.ULong.of_int 16 in
    let high_level = P11_gcm_params.make ~iv ~aad ~tag_bits in
    let low_level = Pkcs11_CK_GCM_PARAMS.make high_level in
    let expected = (iv, aad, tag_bits) in
    let got_iv =
      Ctypes_helpers.view_string
        low_level
        Pkcs11_CK_GCM_PARAMS.ulIvLen
        Pkcs11_CK_GCM_PARAMS.pIv
    in
    let got_aad =
      Ctypes_helpers.view_string
        low_level
        Pkcs11_CK_GCM_PARAMS.ulAADLen
        Pkcs11_CK_GCM_PARAMS.pAAD
    in
    let got_tag_bits =
      Ctypes.getf low_level Pkcs11_CK_GCM_PARAMS.ulTagBits
    in
    let got = (got_iv, got_aad, got_tag_bits) in
    assert_equal
      ~ctxt
      ~cmp:[%eq: string * string * P11_ulong.t]
      ~printer:[%show: string * string * P11_ulong.t]
      expected
      got

let test_view =
  "view" >:: fun ctxt ->
    let iv = "iv" in
    let aad = "aad" in
    let tag_bits = Unsigned.ULong.of_int 16 in
    let low_level = Ctypes.make Pkcs11_CK_GCM_PARAMS.t in
    Ctypes_helpers.make_string iv low_level Pkcs11_CK_GCM_PARAMS.ulIvLen Pkcs11_CK_GCM_PARAMS.pIv;
    Ctypes_helpers.make_string aad low_level Pkcs11_CK_GCM_PARAMS.ulAADLen Pkcs11_CK_GCM_PARAMS.pAAD;
    Ctypes.setf low_level Pkcs11_CK_GCM_PARAMS.ulTagBits tag_bits;
    let expected = P11_gcm_params.make ~iv ~aad ~tag_bits in
    let got = Pkcs11_CK_GCM_PARAMS.view low_level in
    assert_equal
      ~ctxt
      ~cmp:[%eq: P11_gcm_params.t]
      ~printer:[%show: P11_gcm_params.t]
      expected
      got

let suite =
  "CK_GCM_PARAMS" >:::
  [ test_make
  ; test_view
  ]
