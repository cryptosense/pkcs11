open OUnit2

let test_make =
  let check_mechanism_type ~ctxt low expected =
    let got = Ctypes.getf low Pkcs11_CK_MECHANISM.mechanism in
    assert_equal ~ctxt ~cmp:[%eq: Pkcs11_CK_MECHANISM_TYPE.t]
      ~printer:[%show: Pkcs11_CK_MECHANISM_TYPE.t] expected got
  in
  let test_null high expected ctxt =
    let low = Pkcs11_CK_MECHANISM.make high in
    check_mechanism_type ~ctxt low expected;
    let param = Ctypes.getf low Pkcs11_CK_MECHANISM.parameter in
    assert_bool "Parameter should be NULL"
    @@ Ctypes_helpers.Reachable_ptr.is_null param;
    let param_len = Ctypes.getf low Pkcs11_CK_MECHANISM.parameter_len in
    assert_equal ~ctxt ~cmp:[%eq: P11_ulong.t] ~printer:[%show: P11_ulong.t]
      Unsigned.ULong.zero param_len
  in
  let test high expected_type expected_len ctxt =
    let low = Pkcs11_CK_MECHANISM.make high in
    check_mechanism_type ~ctxt low expected_type;
    let param = Ctypes.getf low Pkcs11_CK_MECHANISM.parameter in
    assert_bool "Parameter should not be NULL"
    @@ not
    @@ Ctypes_helpers.Reachable_ptr.is_null param;
    let param_len = Ctypes.getf low Pkcs11_CK_MECHANISM.parameter_len in
    assert_equal ~ctxt ~cmp:[%eq: P11_ulong.t] ~printer:[%show: P11_ulong.t]
      expected_len param_len
  in
  let sizeof_ul typ = Unsigned.ULong.of_int (Ctypes.sizeof typ) in
  "make"
  >::: [ "No parameters"
         >:: test_null P11_mechanism.CKM_SHA_1
               Pkcs11_CK_MECHANISM_TYPE._CKM_SHA_1
       ; "OAEP"
         >:: test
               (P11_mechanism.CKM_RSA_PKCS_OAEP
                  { P11_rsa_pkcs_oaep_params.hashAlg =
                      P11_mechanism_type.CKM_SHA_1
                  ; mgf = P11_rsa_pkcs_mgf_type._CKG_MGF1_SHA1
                  ; src = None })
               Pkcs11_CK_MECHANISM_TYPE._CKM_RSA_PKCS_OAEP
               (sizeof_ul Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.t)
       ; "PSS"
         >:: test
               (P11_mechanism.CKM_RSA_PKCS_PSS
                  { P11_rsa_pkcs_pss_params.hashAlg =
                      P11_mechanism_type.CKM_SHA_1
                  ; mgf = P11_rsa_pkcs_mgf_type._CKG_MGF1_SHA1
                  ; sLen = Unsigned.ULong.zero })
               Pkcs11_CK_MECHANISM_TYPE._CKM_RSA_PKCS_PSS
               (sizeof_ul Pkcs11_CK_RSA_PKCS_PSS_PARAMS.t)
       ; "string"
         >:: test (P11_mechanism.CKM_AES_CBC "string")
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_CBC
               (Unsigned.ULong.of_int (String.length "string"))
       ; "ulong"
         >:: test (P11_mechanism.CKM_AES_MAC_GENERAL Unsigned.ULong.zero)
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_MAC_GENERAL
               (sizeof_ul Ctypes.ulong)
       ; "derivation_string"
         >:: test (P11_mechanism.CKM_AES_ECB_ENCRYPT_DATA "string")
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_ECB_ENCRYPT_DATA
               (sizeof_ul Pkcs11_CK_KEY_DERIVATION_STRING_DATA.t)
       ; "AES CBC params"
         >:: test
               (P11_mechanism.CKM_AES_CBC_ENCRYPT_DATA
                  { P11_aes_cbc_encrypt_data_params.iv = "0123456789abcdef"
                  ; data = "data" })
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_CBC_ENCRYPT_DATA
               (sizeof_ul
                  Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS
                  .t)
       ; "DES CBC params"
         >:: test
               (P11_mechanism.CKM_DES_CBC_ENCRYPT_DATA
                  { P11_des_cbc_encrypt_data_params.iv = "01234567"
                  ; data = "data" })
               Pkcs11_CK_MECHANISM_TYPE._CKM_DES_CBC_ENCRYPT_DATA
               (sizeof_ul
                  Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS
                  .t)
       ; "ECDH1"
         >:: test
               (P11_mechanism.CKM_ECDH1_DERIVE
                  { P11_ecdh1_derive_params.kdf = P11_ec_kdf.CKD_NULL
                  ; shared_data = None
                  ; public_data = "" })
               Pkcs11_CK_MECHANISM_TYPE._CKM_ECDH1_DERIVE
               (sizeof_ul Pkcs11_CK_ECDH1_DERIVE_PARAMS.t)
       ; "ECMQV"
         >:: test
               (P11_mechanism.CKM_ECMQV_DERIVE
                  { P11_ecmqv_derive_params.kdf = P11_ec_kdf.CKD_NULL
                  ; shared_data = None
                  ; public_data = ""
                  ; private_data_len = Unsigned.ULong.zero
                  ; private_data = Unsigned.ULong.zero
                  ; public_data2 = ""
                  ; public_key = Unsigned.ULong.zero })
               Pkcs11_CK_MECHANISM_TYPE._CKM_ECMQV_DERIVE
               (sizeof_ul Pkcs11_CK_ECMQV_DERIVE_PARAMS.t)
       ; "PBKD2"
         >:: test
               (P11_mechanism.CKM_PKCS5_PBKD2
                  { P11_pkcs5_pbkd2_data_params.saltSource =
                      P11_pkcs5_pbkdf2_salt_source_type.CKZ_SALT_SPECIFIED
                  ; saltSourceData = None
                  ; iterations = 0
                  ; prf =
                      P11_pkcs5_pbkd2_pseudo_random_function_type
                      .CKP_PKCS5_PBKD2_HMAC_SHA1
                  ; prfData = None
                  ; password = "" })
               Pkcs11_CK_MECHANISM_TYPE._CKM_PKCS5_PBKD2
               (sizeof_ul Pkcs11_CK_PKCS5_PBKD2_PARAMS.t)
       ; "AES CTR"
         >:: test
               (P11_mechanism.CKM_AES_CTR
                  (P11_aes_ctr_params.make ~bits:Unsigned.ULong.zero ~block:""))
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_CTR
               (sizeof_ul Pkcs11_CK_AES_CTR_PARAMS.t)
       ; "GCM"
         >:: test
               (P11_mechanism.CKM_AES_GCM
                  (P11_gcm_params.make ~iv:"" ~aad:""
                     ~tag_bits:Unsigned.ULong.zero))
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_GCM
               (sizeof_ul Pkcs11_CK_GCM_PARAMS.t)
       ; "AES_KEY_WRAP (null)"
         >:: test_null
               (P11_mechanism.CKM_AES_KEY_WRAP P11_aes_key_wrap_params.default)
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_KEY_WRAP
       ; "AES_KEY_WRAP (with IV)"
         >:: test
               (P11_mechanism.CKM_AES_KEY_WRAP
                  (P11_aes_key_wrap_params.explicit "12345678"))
               Pkcs11_CK_MECHANISM_TYPE._CKM_AES_KEY_WRAP
               (Unsigned.ULong.of_int 8) ]

let test_view =
  let test low expected ctxt =
    let got = Pkcs11_CK_MECHANISM.view low in
    assert_equal ~ctxt ~cmp:[%eq: P11_mechanism.t]
      ~printer:[%show: P11_mechanism.t] expected got
  in
  let build_fields ~mechanism_type ~parameter ~parameter_len =
    let m = Ctypes.make Pkcs11_CK_MECHANISM.ck_mechanism in
    Ctypes.setf m Pkcs11_CK_MECHANISM.mechanism mechanism_type;
    Ctypes_helpers.Reachable_ptr.setf m Pkcs11_CK_MECHANISM.parameter parameter;
    Ctypes.setf m Pkcs11_CK_MECHANISM.parameter_len parameter_len;
    m
  in
  let build mechanism_type =
    build_fields ~mechanism_type ~parameter:Ctypes.null
      ~parameter_len:Unsigned.ULong.zero
  in
  let build_string mechanism_type s =
    let data = Pkcs11_data.of_string s in
    let parameter = Ctypes.to_voidp (Pkcs11_data.get_content data) in
    let parameter_len = Pkcs11_data.get_length data in
    build_fields ~mechanism_type ~parameter ~parameter_len
  in
  "view"
  >::: [ "known with binding"
         >:: test
               (build Pkcs11_CK_MECHANISM_TYPE._CKM_SHA_1)
               P11_mechanism.CKM_SHA_1
       ; "known with no binding"
         >:: test
               (build Pkcs11_CK_MECHANISM_TYPE._CKM_GOSTR3411)
               (P11_mechanism.CKM_CS_UNKNOWN
                  Pkcs11_CK_MECHANISM_TYPE._CKM_GOSTR3411)
       ; "CKM_AES_KEY_WRAP with no IV"
         >:: test
               (build Pkcs11_CK_MECHANISM_TYPE._CKM_AES_KEY_WRAP)
               (P11_mechanism.CKM_AES_KEY_WRAP P11_aes_key_wrap_params.default)
       ; "CKM_AES_KEY_WRAP with an IV"
         >:: test
               (build_string Pkcs11_CK_MECHANISM_TYPE._CKM_AES_KEY_WRAP
                  "12345678")
               (P11_mechanism.CKM_AES_KEY_WRAP
                  (P11_aes_key_wrap_params.explicit "12345678")) ]

let suite = "CK_MECHANISM" >::: [test_make; test_view]
