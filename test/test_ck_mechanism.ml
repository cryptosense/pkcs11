open OUnit2

let test_make =
  let test high expected ctxt =
    let low = Pkcs11_CK_MECHANISM.make high in
    let got = Ctypes.getf low Pkcs11_CK_MECHANISM.mechanism in
    assert_equal
      ~ctxt
      ~cmp:[%eq: Pkcs11_CK_MECHANISM_TYPE.t]
      ~printer:[%show: Pkcs11_CK_MECHANISM_TYPE.t]
      expected
      got

  in
  "make" >:::
  [ "No parameters" >:: test
      P11_mechanism.CKM_SHA_1
      Pkcs11_CK_MECHANISM_TYPE._CKM_SHA_1
  ; "OAEP" >:: test
      ( P11_mechanism.CKM_RSA_PKCS_OAEP
          { P11_rsa_pkcs_oaep_params.hashAlg = P11_mechanism_type.CKM_SHA_1
          ; mgf = P11_rsa_pkcs_mgf_type._CKG_MGF1_SHA1
          ; src = None
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_RSA_PKCS_OAEP
  ; "PSS" >:: test
      ( P11_mechanism.CKM_RSA_PKCS_PSS
          { P11_rsa_pkcs_pss_params.hashAlg = P11_mechanism_type.CKM_SHA_1
          ; mgf = P11_rsa_pkcs_mgf_type._CKG_MGF1_SHA1
          ; sLen = Unsigned.ULong.zero
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_RSA_PKCS_PSS
  ; "string" >:: test
      (P11_mechanism.CKM_AES_CBC "string")
      Pkcs11_CK_MECHANISM_TYPE._CKM_AES_CBC
  ; "ulong" >:: test
      (P11_mechanism.CKM_AES_MAC_GENERAL Unsigned.ULong.zero)
      Pkcs11_CK_MECHANISM_TYPE._CKM_AES_MAC_GENERAL
  ; "derivation_string" >:: test
      (P11_mechanism.CKM_AES_ECB_ENCRYPT_DATA "string")
      Pkcs11_CK_MECHANISM_TYPE._CKM_AES_ECB_ENCRYPT_DATA
  ; "AES CBC params" >:: test
      ( P11_mechanism.CKM_AES_CBC_ENCRYPT_DATA
          { P11_aes_cbc_encrypt_data_params.iv = "0123456789abcdef"
          ; data = "data"
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_AES_CBC_ENCRYPT_DATA
  ; "DES CBC params" >:: test
      ( P11_mechanism.CKM_DES_CBC_ENCRYPT_DATA
          { P11_des_cbc_encrypt_data_params.iv = "01234567"
          ; data = "data"
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_DES_CBC_ENCRYPT_DATA
  ; "ECDH1" >:: test
      ( P11_mechanism.CKM_ECDH1_DERIVE
          { P11_ecdh1_derive_params.kdf = P11_ec_kdf.CKD_NULL
          ; shared_data = None
          ; public_data = ""
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_ECDH1_DERIVE
  ; "ECMQV" >:: test
      ( P11_mechanism.CKM_ECMQV_DERIVE
          { P11_ecmqv_derive_params.kdf = P11_ec_kdf.CKD_NULL
          ; shared_data = None
          ; public_data = ""
          ; private_data_len = Unsigned.ULong.zero
          ; private_data = Unsigned.ULong.zero
          ; public_data2 = ""
          ; public_key = Unsigned.ULong.zero
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_ECMQV_DERIVE
  ; "PBKD2" >:: test
      ( P11_mechanism.CKM_PKCS5_PBKD2
          { P11_pkcs5_pbkd2_data_params.saltSource =
              P11_pkcs5_pbkdf2_salt_source_type.CKZ_SALT_SPECIFIED
          ; saltSourceData = None
          ; iterations = 0
          ; prf = P11_pkcs5_pbkd2_pseudo_random_function_type.CKP_PKCS5_PBKD2_HMAC_SHA1
          ; prfData = None
          ; password = ""
          }
      )
      Pkcs11_CK_MECHANISM_TYPE._CKM_PKCS5_PBKD2
  ]

let suite =
  "CK_MECHANISM" >:::
  [ test_make
  ]
