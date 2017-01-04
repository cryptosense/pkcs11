(** Support missing for a given mechanism   *)
exception Mechanism_not_supported of string

let key_type (m : Pkcs11.CK_MECHANISM_TYPE.u) : Pkcs11.CK_KEY_TYPE.u option =
  let open Pkcs11.CK_MECHANISM_TYPE in
  let open Pkcs11.CK_KEY_TYPE in
  let some x = Some x in
  let none = None in
  let fail () = raise @@ Mechanism_not_supported ((* Pkcs11.CK_MECHANISM.mechanism_type m *)
                                               (* |> *) Pkcs11.CK_MECHANISM_TYPE.to_string m) in
  match m with
    | CKM_RSA_PKCS_KEY_PAIR_GEN  -> some CKK_RSA
    | CKM_RSA_PKCS  -> some CKK_RSA
    | CKM_RSA_9796  -> some CKK_RSA
    | CKM_RSA_X_509  -> some CKK_RSA
    | CKM_MD2_RSA_PKCS  -> some CKK_RSA
    | CKM_MD5_RSA_PKCS  -> some CKK_RSA
    | CKM_SHA1_RSA_PKCS  -> some CKK_RSA
    | CKM_RIPEMD128_RSA_PKCS  -> some CKK_RSA
    | CKM_RIPEMD160_RSA_PKCS  -> some CKK_RSA
    | CKM_RSA_PKCS_OAEP  -> some CKK_RSA
    | CKM_RSA_X9_31_KEY_PAIR_GEN  -> some CKK_RSA
    | CKM_RSA_X9_31  -> some CKK_RSA
    | CKM_SHA1_RSA_X9_31  -> some CKK_RSA
    | CKM_RSA_PKCS_PSS  -> some CKK_RSA
    | CKM_SHA1_RSA_PKCS_PSS  -> some CKK_RSA
    | CKM_DSA_KEY_PAIR_GEN  -> some CKK_DSA
    | CKM_DSA  -> some CKK_DSA
    | CKM_DSA_SHA1  -> some CKK_DSA
    | CKM_DH_PKCS_KEY_PAIR_GEN  -> some CKK_DH
    | CKM_DH_PKCS_DERIVE  -> some CKK_DH
    | CKM_X9_42_DH_KEY_PAIR_GEN  -> some CKK_DH
    | CKM_X9_42_DH_DERIVE  -> some CKK_DH
    | CKM_X9_42_DH_HYBRID_DERIVE  -> some CKK_DH
    | CKM_X9_42_MQV_DERIVE  -> some CKK_DH
    | CKM_SHA256_RSA_PKCS  -> some CKK_RSA
    | CKM_SHA384_RSA_PKCS  -> some CKK_RSA
    | CKM_SHA512_RSA_PKCS  -> some CKK_RSA
    | CKM_SHA256_RSA_PKCS_PSS  -> some CKK_RSA
    | CKM_SHA384_RSA_PKCS_PSS  -> some CKK_RSA
    | CKM_SHA512_RSA_PKCS_PSS  -> some CKK_RSA
    | CKM_SHA224_RSA_PKCS  -> some CKK_RSA
    | CKM_SHA224_RSA_PKCS_PSS  -> some CKK_RSA
    | CKM_RC2_KEY_GEN  -> some CKK_RC2
    | CKM_RC2_ECB  -> some CKK_RC2
    | CKM_RC2_CBC  -> some CKK_RC2
    | CKM_RC2_MAC  -> some CKK_RC2
    | CKM_RC2_MAC_GENERAL  -> some CKK_RC2
    | CKM_RC2_CBC_PAD  -> some CKK_RC2
    | CKM_RC4_KEY_GEN  -> some CKK_RC4
    | CKM_RC4  -> some CKK_RC4
    | CKM_DES_KEY_GEN  -> some CKK_DES
    | CKM_DES_ECB  -> some CKK_DES
    | CKM_DES_CBC  -> some CKK_DES
    | CKM_DES_MAC  -> some CKK_DES
    | CKM_DES_MAC_GENERAL  -> some CKK_DES
    | CKM_DES_CBC_PAD  -> some CKK_DES
    | CKM_DES2_KEY_GEN  -> some CKK_DES3 (* should be CKK_DES2 *)
    | CKM_DES3_KEY_GEN  -> some CKK_DES3
    | CKM_DES3_ECB  -> some CKK_DES3
    | CKM_DES3_CBC  -> some CKK_DES3
    | CKM_DES3_MAC  -> some CKK_DES3
    | CKM_DES3_MAC_GENERAL  -> some CKK_DES3
    | CKM_DES3_CBC_PAD  -> some CKK_DES3
    | CKM_CDMF_KEY_GEN  -> some CKK_CDMF
    | CKM_CDMF_ECB  -> some CKK_CDMF
    | CKM_CDMF_CBC  -> some CKK_CDMF
    | CKM_CDMF_MAC  -> some CKK_CDMF
    | CKM_CDMF_MAC_GENERAL  -> some CKK_CDMF
    | CKM_CDMF_CBC_PAD  -> some CKK_CDMF
    | CKM_DES_OFB64  -> some CKK_DES
    | CKM_DES_OFB8  -> some CKK_DES
    | CKM_DES_CFB64  -> some CKK_DES
    | CKM_DES_CFB8  -> some CKK_DES
    | CKM_MD2  -> none
    | CKM_MD2_HMAC  -> none
    | CKM_MD2_HMAC_GENERAL  -> none
    | CKM_MD5  -> none
    | CKM_MD5_HMAC  -> none
    | CKM_MD5_HMAC_GENERAL  -> none
    | CKM_SHA_1  -> none
    | CKM_SHA_1_HMAC  -> none
    | CKM_SHA_1_HMAC_GENERAL  -> none
    | CKM_RIPEMD128  -> none
    | CKM_RIPEMD128_HMAC  -> none
    | CKM_RIPEMD128_HMAC_GENERAL  -> none
    | CKM_RIPEMD160  -> none
    | CKM_RIPEMD160_HMAC  -> none
    | CKM_RIPEMD160_HMAC_GENERAL  -> none
    | CKM_SHA256  -> none
    | CKM_SHA256_HMAC  -> none
    | CKM_SHA256_HMAC_GENERAL  -> none
    | CKM_SHA224  -> none
    | CKM_SHA224_HMAC  -> none
    | CKM_SHA224_HMAC_GENERAL  -> none
    | CKM_SHA384  -> none
    | CKM_SHA384_HMAC  -> none
    | CKM_SHA384_HMAC_GENERAL  -> none
    | CKM_SHA512  -> none
    | CKM_SHA512_HMAC  -> none
    | CKM_SHA512_HMAC_GENERAL  -> none
    | CKM_SECURID_KEY_GEN  -> some CKK_SECURID
    | CKM_SECURID  -> some CKK_SECURID
    | CKM_HOTP_KEY_GEN  -> some CKK_HOTP
    | CKM_HOTP  -> some CKK_HOTP
    | CKM_ACTI  -> some CKK_ACTI
    | CKM_ACTI_KEY_GEN  -> some CKK_ACTI
    | CKM_CAST_KEY_GEN  -> some CKK_CAST
    | CKM_CAST_ECB  -> some CKK_CAST
    | CKM_CAST_CBC  -> some CKK_CAST
    | CKM_CAST_MAC  -> some CKK_CAST
    | CKM_CAST_MAC_GENERAL  -> some CKK_CAST
    | CKM_CAST_CBC_PAD  -> some CKK_CAST
    | CKM_CAST3_KEY_GEN  -> some CKK_CAST3
    | CKM_CAST3_ECB  -> some CKK_CAST3
    | CKM_CAST3_CBC  -> some CKK_CAST3
    | CKM_CAST3_MAC  -> some CKK_CAST3
    | CKM_CAST3_MAC_GENERAL  -> some CKK_CAST3
    | CKM_CAST3_CBC_PAD  -> some CKK_CAST3
    | CKM_CAST128_KEY_GEN  -> some CKK_CAST128
    | CKM_CAST128_ECB  -> some CKK_CAST128
    | CKM_CAST128_CBC  -> some CKK_CAST128
    | CKM_CAST128_MAC  -> some CKK_CAST128
    | CKM_CAST128_MAC_GENERAL  -> some CKK_CAST128
    | CKM_CAST128_CBC_PAD  -> some CKK_CAST128
    | CKM_RC5_KEY_GEN  -> some CKK_RC5
    | CKM_RC5_ECB  -> some CKK_RC5
    | CKM_RC5_CBC  -> some CKK_RC5
    | CKM_RC5_MAC  -> some CKK_RC5
    | CKM_RC5_MAC_GENERAL  -> some CKK_RC5
    | CKM_RC5_CBC_PAD  -> some CKK_RC5
    | CKM_IDEA_KEY_GEN  -> some CKK_IDEA
    | CKM_IDEA_ECB  -> some CKK_IDEA
    | CKM_IDEA_CBC  -> some CKK_IDEA
    | CKM_IDEA_MAC  -> some CKK_IDEA
    | CKM_IDEA_MAC_GENERAL  -> some CKK_IDEA
    | CKM_IDEA_CBC_PAD  -> some CKK_IDEA
    | CKM_GENERIC_SECRET_KEY_GEN  -> some CKK_GENERIC_SECRET
    | CKM_CONCATENATE_BASE_AND_KEY  -> none
    | CKM_CONCATENATE_BASE_AND_DATA  -> none
    | CKM_CONCATENATE_DATA_AND_BASE  -> none
    | CKM_XOR_BASE_AND_DATA  -> none
    | CKM_EXTRACT_KEY_FROM_KEY  -> none
    | CKM_SSL3_PRE_MASTER_KEY_GEN  -> fail ()
    | CKM_SSL3_MASTER_KEY_DERIVE  -> fail ()
    | CKM_SSL3_KEY_AND_MAC_DERIVE  -> fail ()
    | CKM_SSL3_MASTER_KEY_DERIVE_DH  -> fail ()
    | CKM_TLS_PRE_MASTER_KEY_GEN  -> fail ()
    | CKM_TLS_MASTER_KEY_DERIVE  -> fail ()
    | CKM_TLS_KEY_AND_MAC_DERIVE  -> fail ()
    | CKM_TLS_MASTER_KEY_DERIVE_DH  -> fail ()
    | CKM_TLS_PRF  -> fail ()
    | CKM_SSL3_MD5_MAC  -> fail ()
    | CKM_SSL3_SHA1_MAC  -> fail ()
    | CKM_MD5_KEY_DERIVATION  -> none
    | CKM_MD2_KEY_DERIVATION  -> none
    | CKM_SHA1_KEY_DERIVATION  -> none
    | CKM_SHA256_KEY_DERIVATION  -> none
    | CKM_SHA384_KEY_DERIVATION  -> none
    | CKM_SHA512_KEY_DERIVATION  -> none
    | CKM_SHA224_KEY_DERIVATION  -> none

    | CKM_PBE_MD2_DES_CBC  -> none
    | CKM_PBE_MD5_DES_CBC  -> none
    | CKM_PBE_MD5_CAST_CBC  -> none
    | CKM_PBE_MD5_CAST3_CBC  -> none
    | CKM_PBE_MD5_CAST128_CBC  -> none
    | CKM_PBE_SHA1_CAST128_CBC  -> none
    | CKM_PBE_SHA1_RC4_128  -> none
    | CKM_PBE_SHA1_RC4_40  -> none
    | CKM_PBE_SHA1_DES3_EDE_CBC  -> none
    | CKM_PBE_SHA1_DES2_EDE_CBC  -> none
    | CKM_PBE_SHA1_RC2_128_CBC  -> none
    | CKM_PBE_SHA1_RC2_40_CBC  -> none

    | CKM_PKCS5_PBKD2  -> none
    | CKM_PBA_SHA1_WITH_SHA1_HMAC  -> fail ()
    | CKM_WTLS_PRE_MASTER_KEY_GEN  -> fail ()
    | CKM_WTLS_MASTER_KEY_DERIVE  -> fail ()
    | CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC  -> fail ()
    | CKM_WTLS_PRF  -> fail ()
    | CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  -> fail ()
    | CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  -> fail ()
    | CKM_KEY_WRAP_LYNKS  -> fail ()
    | CKM_KEY_WRAP_SET_OAEP  -> fail ()
    | CKM_CMS_SIG  -> fail ()
    | CKM_KIP_DERIVE  -> fail ()
    | CKM_KIP_WRAP  -> fail ()
    | CKM_KIP_MAC  -> fail ()
    | CKM_CAMELLIA_KEY_GEN  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_ECB  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_CBC  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_MAC  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_MAC_GENERAL  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_CBC_PAD  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_ECB_ENCRYPT_DATA  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_CBC_ENCRYPT_DATA  -> some CKK_CAMELLIA
    | CKM_CAMELLIA_CTR  -> some CKK_CAMELLIA
    | CKM_ARIA_KEY_GEN  -> some CKK_ARIA
    | CKM_ARIA_ECB  -> some CKK_ARIA
    | CKM_ARIA_CBC  -> some CKK_ARIA
    | CKM_ARIA_MAC  -> some CKK_ARIA
    | CKM_ARIA_MAC_GENERAL  -> some CKK_ARIA
    | CKM_ARIA_CBC_PAD  -> some CKK_ARIA
    | CKM_ARIA_ECB_ENCRYPT_DATA  -> some CKK_ARIA
    | CKM_ARIA_CBC_ENCRYPT_DATA  -> some CKK_ARIA
    | CKM_SKIPJACK_KEY_GEN  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_ECB64  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_CBC64  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_OFB64  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_CFB64  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_CFB32  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_CFB16  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_CFB8  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_WRAP  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_PRIVATE_WRAP  -> some CKK_SKIPJACK
    | CKM_SKIPJACK_RELAYX  -> some CKK_SKIPJACK
    | CKM_KEA_KEY_PAIR_GEN  -> some CKK_KEA
    | CKM_KEA_KEY_DERIVE  -> some CKK_KEA
    | CKM_FORTEZZA_TIMESTAMP  -> fail () (* CKK_DSA? *)
    | CKM_BATON_KEY_GEN  -> some CKK_BATON
    | CKM_BATON_ECB128  -> some CKK_BATON
    | CKM_BATON_ECB96  -> some CKK_BATON
    | CKM_BATON_CBC128  -> some CKK_BATON
    | CKM_BATON_COUNTER  -> some CKK_BATON
    | CKM_BATON_SHUFFLE  -> some CKK_BATON
    | CKM_BATON_WRAP  -> some CKK_BATON
    | CKM_EC_KEY_PAIR_GEN  -> some CKK_EC
    | CKM_ECDSA  -> some CKK_EC
    | CKM_ECDSA_SHA1  -> some CKK_EC
    | CKM_ECDH1_DERIVE  -> some CKK_EC
    | CKM_ECDH1_COFACTOR_DERIVE  -> some CKK_EC
    | CKM_ECMQV_DERIVE  -> some CKK_EC
    | CKM_JUNIPER_KEY_GEN  -> some CKK_JUNIPER
    | CKM_JUNIPER_ECB128  -> some CKK_JUNIPER
    | CKM_JUNIPER_CBC128  -> some CKK_JUNIPER
    | CKM_JUNIPER_COUNTER  -> some CKK_JUNIPER
    | CKM_JUNIPER_SHUFFLE  -> some CKK_JUNIPER
    | CKM_JUNIPER_WRAP  -> some CKK_JUNIPER
    | CKM_FASTHASH  -> fail ()
    | CKM_AES_KEY_GEN  -> some CKK_AES
    | CKM_AES_ECB  -> some CKK_AES
    | CKM_AES_CBC  -> some CKK_AES
    | CKM_AES_MAC  -> some CKK_AES
    | CKM_AES_MAC_GENERAL  -> some CKK_AES
    | CKM_AES_CBC_PAD  -> some CKK_AES
    | CKM_AES_CTR  -> some CKK_AES
    | CKM_BLOWFISH_KEY_GEN  -> some CKK_BLOWFISH
    | CKM_BLOWFISH_CBC  -> some CKK_BLOWFISH
    | CKM_TWOFISH_KEY_GEN  -> some CKK_TWOFISH
    | CKM_TWOFISH_CBC  -> some CKK_TWOFISH
    | CKM_DES_ECB_ENCRYPT_DATA  -> some CKK_DES
    | CKM_DES_CBC_ENCRYPT_DATA  -> some CKK_DES
    | CKM_DES3_ECB_ENCRYPT_DATA  -> some CKK_DES3
    | CKM_DES3_CBC_ENCRYPT_DATA  -> some CKK_DES3
    | CKM_AES_ECB_ENCRYPT_DATA  -> some CKK_AES
    | CKM_AES_CBC_ENCRYPT_DATA  -> some CKK_AES
    | CKM_DSA_PARAMETER_GEN  -> some CKK_DSA
    | CKM_DH_PKCS_PARAMETER_GEN  -> some CKK_DH
    | CKM_X9_42_DH_PARAMETER_GEN  -> some CKK_DH
    | CKM_VENDOR_DEFINED  -> fail ()
    | CKM_CS_UNKNOWN _ -> none
