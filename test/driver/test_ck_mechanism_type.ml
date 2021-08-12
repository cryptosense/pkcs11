open OUnit2

let test_v2_40 =
  let test code _ctxt =
    let is_known =
      let open P11_mechanism_type in
      match Pkcs11_CK_MECHANISM_TYPE.view @@ Unsigned.ULong.of_int code with
      | CKM_CS_UNKNOWN _ -> false
      | _ -> true
    in
    let msg = Printf.sprintf "Mechanism type should be known: 0x%x" code in
    assert_bool msg is_known
  in
  "2.40 mechanisms"
  >::: [ "CKM_DSA_SHA224" >:: test 0x00000013
       ; "CKM_DSA_SHA256" >:: test 0x00000014
       ; "CKM_DSA_SHA384" >:: test 0x00000015
       ; "CKM_DSA_SHA512" >:: test 0x00000016
       ; "CKM_SHA512_224" >:: test 0x00000048
       ; "CKM_SHA512_224_HMAC" >:: test 0x00000049
       ; "CKM_SHA512_224_HMAC_GENERAL" >:: test 0x0000004A
       ; "CKM_SHA512_224_KEY_DERIVATION" >:: test 0x0000004B
       ; "CKM_SHA512_256" >:: test 0x0000004C
       ; "CKM_SHA512_256_HMAC" >:: test 0x0000004D
       ; "CKM_SHA512_256_HMAC_GENERAL" >:: test 0x0000004E
       ; "CKM_SHA512_256_KEY_DERIVATION" >:: test 0x0000004F
       ; "CKM_SHA512_T" >:: test 0x00000050
       ; "CKM_SHA512_T_HMAC" >:: test 0x00000051
       ; "CKM_SHA512_T_HMAC_GENERAL" >:: test 0x00000052
       ; "CKM_SHA512_T_KEY_DERIVATION" >:: test 0x00000053
       ; "CKM_DES3_CMAC_GENERAL" >:: test 0x00000137
       ; "CKM_DES3_CMAC" >:: test 0x00000138
       ; "CKM_TLS10_MAC_SERVER" >:: test 0x000003D6
       ; "CKM_TLS10_MAC_CLIENT" >:: test 0x000003D7
       ; "CKM_TLS12_MAC" >:: test 0x000003D8
       ; "CKM_TLS12_KDF" >:: test 0x000003D9
       ; "CKM_TLS12_MASTER_KEY_DERIVE" >:: test 0x000003E0
       ; "CKM_TLS12_KEY_AND_MAC_DERIVE" >:: test 0x000003E1
       ; "CKM_TLS12_MASTER_KEY_DERIVE_DH" >:: test 0x000003E2
       ; "CKM_TLS12_KEY_SAFE_DERIVE" >:: test 0x000003E3
       ; "CKM_TLS_MAC" >:: test 0x000003E4
       ; "CKM_TLS_KDF" >:: test 0x000003E5
       ; "CKM_SEED_KEY_GEN" >:: test 0x00000650
       ; "CKM_SEED_ECB" >:: test 0x00000651
       ; "CKM_SEED_CBC" >:: test 0x00000652
       ; "CKM_SEED_MAC" >:: test 0x00000653
       ; "CKM_SEED_MAC_GENERAL" >:: test 0x00000654
       ; "CKM_SEED_CBC_PAD" >:: test 0x00000655
       ; "CKM_SEED_ECB_ENCRYPT_DATA" >:: test 0x00000656
       ; "CKM_SEED_CBC_ENCRYPT_DATA" >:: test 0x00000657
       ; "CKM_KEA_DERIVE" >:: test 0x00001012
       ; "CKM_ECDSA_SHA224" >:: test 0x00001043
       ; "CKM_ECDSA_SHA256" >:: test 0x00001044
       ; "CKM_ECDSA_SHA384" >:: test 0x00001045
       ; "CKM_ECDSA_SHA512" >:: test 0x00001046
       ; "CKM_ECDH_AES_KEY_WRAP" >:: test 0x00001053
       ; "CKM_RSA_AES_KEY_WRAP" >:: test 0x00001054
       ; "CKM_AES_GCM" >:: test 0x00001087
       ; "CKM_AES_CCM" >:: test 0x00001088
       ; "CKM_AES_CTS" >:: test 0x00001089
       ; "CKM_AES_CMAC" >:: test 0x0000108A
       ; "CKM_AES_CMAC_GENERAL" >:: test 0x0000108B
       ; "CKM_AES_XCBC_MAC" >:: test 0x0000108C
       ; "CKM_AES_XCBC_MAC_96" >:: test 0x0000108D
       ; "CKM_AES_GMAC" >:: test 0x0000108E
       ; "CKM_BLOWFISH_CBC_PAD" >:: test 0x00001094
       ; "CKM_TWOFISH_CBC_PAD" >:: test 0x00001095
       ; "CKM_GOSTR3410_KEY_PAIR_GEN" >:: test 0x00001200
       ; "CKM_GOSTR3410" >:: test 0x00001201
       ; "CKM_GOSTR3410_WITH_GOSTR3411" >:: test 0x00001202
       ; "CKM_GOSTR3410_KEY_WRAP" >:: test 0x00001203
       ; "CKM_GOSTR3410_DERIVE" >:: test 0x00001204
       ; "CKM_GOSTR3411" >:: test 0x00001210
       ; "CKM_GOSTR3411_HMAC" >:: test 0x00001211
       ; "CKM_GOST28147_KEY_GEN" >:: test 0x00001220
       ; "CKM_GOST28147_ECB" >:: test 0x00001221
       ; "CKM_GOST28147" >:: test 0x00001222
       ; "CKM_GOST28147_MAC" >:: test 0x00001223
       ; "CKM_GOST28147_KEY_WRAP" >:: test 0x00001224
       ; "CKM_DSA_PROBABLISTIC_PARAMETER_GEN" >:: test 0x00002003
       ; "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN" >:: test 0x00002004
       ; "CKM_AES_OFB" >:: test 0x00002104
       ; "CKM_AES_CFB64" >:: test 0x00002105
       ; "CKM_AES_CFB8" >:: test 0x00002106
       ; "CKM_AES_CFB128" >:: test 0x00002107
       ; "CKM_AES_CFB1" >:: test 0x00002108
       ; "CKM_AES_KEY_WRAP" >:: test 0x00002109
       ; "CKM_AES_KEY_WRAP_PAD" >:: test 0x0000210A
       ; "CKM_RSA_PKCS_TPM_1_1" >:: test 0x00004001
       ; "CKM_RSA_PKCS_OAEP_TPM_1_1" >:: test 0x00004002 ]

let suite = "CK_MECHANISM_TYPE" >::: [test_v2_40]
