type t =
  | CKM_RSA_PKCS_KEY_PAIR_GEN
  | CKM_RSA_PKCS
  | CKM_RSA_9796
  | CKM_RSA_X_509
  | CKM_MD2_RSA_PKCS
  | CKM_MD5_RSA_PKCS
  | CKM_SHA1_RSA_PKCS
  | CKM_RIPEMD128_RSA_PKCS
  | CKM_RIPEMD160_RSA_PKCS
  | CKM_RSA_PKCS_OAEP
  | CKM_RSA_X9_31_KEY_PAIR_GEN
  | CKM_RSA_X9_31
  | CKM_SHA1_RSA_X9_31
  | CKM_RSA_PKCS_PSS
  | CKM_SHA1_RSA_PKCS_PSS
  | CKM_DSA_KEY_PAIR_GEN
  | CKM_DSA
  | CKM_DSA_SHA1
  | CKM_DSA_SHA224
  | CKM_DSA_SHA256
  | CKM_DSA_SHA384
  | CKM_DSA_SHA512
  | CKM_DH_PKCS_KEY_PAIR_GEN
  | CKM_DH_PKCS_DERIVE
  | CKM_X9_42_DH_KEY_PAIR_GEN
  | CKM_X9_42_DH_DERIVE
  | CKM_X9_42_DH_HYBRID_DERIVE
  | CKM_X9_42_MQV_DERIVE
  | CKM_SHA256_RSA_PKCS
  | CKM_SHA384_RSA_PKCS
  | CKM_SHA512_RSA_PKCS
  | CKM_SHA256_RSA_PKCS_PSS
  | CKM_SHA384_RSA_PKCS_PSS
  | CKM_SHA512_RSA_PKCS_PSS
  | CKM_SHA224_RSA_PKCS
  | CKM_SHA224_RSA_PKCS_PSS
  | CKM_RC2_KEY_GEN
  | CKM_RC2_ECB
  | CKM_RC2_CBC
  | CKM_RC2_MAC
  | CKM_RC2_MAC_GENERAL
  | CKM_RC2_CBC_PAD
  | CKM_RC4_KEY_GEN
  | CKM_RC4
  | CKM_DES_KEY_GEN
  | CKM_DES_ECB
  | CKM_DES_CBC
  | CKM_DES_MAC
  | CKM_DES_MAC_GENERAL
  | CKM_DES_CBC_PAD
  | CKM_DES2_KEY_GEN
  | CKM_DES3_KEY_GEN
  | CKM_DES3_ECB
  | CKM_DES3_CBC
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL
  | CKM_DES3_CBC_PAD
  | CKM_CDMF_KEY_GEN
  | CKM_CDMF_ECB
  | CKM_CDMF_CBC
  | CKM_CDMF_MAC
  | CKM_CDMF_MAC_GENERAL
  | CKM_CDMF_CBC_PAD
  | CKM_DES_OFB64
  | CKM_DES_OFB8
  | CKM_DES_CFB64
  | CKM_DES_CFB8
  | CKM_MD2
  | CKM_MD2_HMAC
  | CKM_MD2_HMAC_GENERAL
  | CKM_MD5
  | CKM_MD5_HMAC
  | CKM_MD5_HMAC_GENERAL
  | CKM_SHA_1
  | CKM_SHA_1_HMAC
  | CKM_SHA_1_HMAC_GENERAL
  | CKM_RIPEMD128
  | CKM_RIPEMD128_HMAC
  | CKM_RIPEMD128_HMAC_GENERAL
  | CKM_RIPEMD160
  | CKM_RIPEMD160_HMAC
  | CKM_RIPEMD160_HMAC_GENERAL
  | CKM_SHA256
  | CKM_SHA256_HMAC
  | CKM_SHA256_HMAC_GENERAL
  | CKM_SHA224
  | CKM_SHA224_HMAC
  | CKM_SHA224_HMAC_GENERAL
  | CKM_SHA384
  | CKM_SHA384_HMAC
  | CKM_SHA384_HMAC_GENERAL
  | CKM_SHA512
  | CKM_SHA512_HMAC
  | CKM_SHA512_HMAC_GENERAL
  | CKM_SECURID_KEY_GEN
  | CKM_SECURID
  | CKM_HOTP_KEY_GEN
  | CKM_HOTP
  | CKM_ACTI
  | CKM_ACTI_KEY_GEN
  | CKM_CAST_KEY_GEN
  | CKM_CAST_ECB
  | CKM_CAST_CBC
  | CKM_CAST_MAC
  | CKM_CAST_MAC_GENERAL
  | CKM_CAST_CBC_PAD
  | CKM_CAST3_KEY_GEN
  | CKM_CAST3_ECB
  | CKM_CAST3_CBC
  | CKM_CAST3_MAC
  | CKM_CAST3_MAC_GENERAL
  | CKM_CAST3_CBC_PAD
  | CKM_CAST128_KEY_GEN
  | CKM_CAST128_ECB
  | CKM_CAST128_CBC
  | CKM_CAST128_MAC
  | CKM_CAST128_MAC_GENERAL
  | CKM_CAST128_CBC_PAD
  | CKM_RC5_KEY_GEN
  | CKM_RC5_ECB
  | CKM_RC5_CBC
  | CKM_RC5_MAC
  | CKM_RC5_MAC_GENERAL
  | CKM_RC5_CBC_PAD
  | CKM_IDEA_KEY_GEN
  | CKM_IDEA_ECB
  | CKM_IDEA_CBC
  | CKM_IDEA_MAC
  | CKM_IDEA_MAC_GENERAL
  | CKM_IDEA_CBC_PAD
  | CKM_GENERIC_SECRET_KEY_GEN
  | CKM_CONCATENATE_BASE_AND_KEY
  | CKM_CONCATENATE_BASE_AND_DATA
  | CKM_CONCATENATE_DATA_AND_BASE
  | CKM_XOR_BASE_AND_DATA
  | CKM_EXTRACT_KEY_FROM_KEY
  | CKM_SSL3_PRE_MASTER_KEY_GEN
  | CKM_SSL3_MASTER_KEY_DERIVE
  | CKM_SSL3_KEY_AND_MAC_DERIVE
  | CKM_SSL3_MASTER_KEY_DERIVE_DH
  | CKM_TLS_PRE_MASTER_KEY_GEN
  | CKM_TLS_MASTER_KEY_DERIVE
  | CKM_TLS_KEY_AND_MAC_DERIVE
  | CKM_TLS_MASTER_KEY_DERIVE_DH
  | CKM_TLS_PRF
  | CKM_SSL3_MD5_MAC
  | CKM_SSL3_SHA1_MAC
  | CKM_MD5_KEY_DERIVATION
  | CKM_MD2_KEY_DERIVATION
  | CKM_SHA1_KEY_DERIVATION
  | CKM_SHA256_KEY_DERIVATION
  | CKM_SHA384_KEY_DERIVATION
  | CKM_SHA512_KEY_DERIVATION
  | CKM_SHA224_KEY_DERIVATION
  | CKM_PBE_MD2_DES_CBC
  | CKM_PBE_MD5_DES_CBC
  | CKM_PBE_MD5_CAST_CBC
  | CKM_PBE_MD5_CAST3_CBC
  | CKM_PBE_MD5_CAST128_CBC
  | CKM_PBE_SHA1_CAST128_CBC
  | CKM_PBE_SHA1_RC4_128
  | CKM_PBE_SHA1_RC4_40
  | CKM_PBE_SHA1_DES3_EDE_CBC
  | CKM_PBE_SHA1_DES2_EDE_CBC
  | CKM_PBE_SHA1_RC2_128_CBC
  | CKM_PBE_SHA1_RC2_40_CBC
  | CKM_PKCS5_PBKD2
  | CKM_PBA_SHA1_WITH_SHA1_HMAC
  | CKM_WTLS_PRE_MASTER_KEY_GEN
  | CKM_WTLS_MASTER_KEY_DERIVE
  | CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
  | CKM_WTLS_PRF
  | CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
  | CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
  | CKM_KEY_WRAP_LYNKS
  | CKM_KEY_WRAP_SET_OAEP
  | CKM_CMS_SIG
  | CKM_KIP_DERIVE
  | CKM_KIP_WRAP
  | CKM_KIP_MAC
  | CKM_CAMELLIA_KEY_GEN
  | CKM_CAMELLIA_ECB
  | CKM_CAMELLIA_CBC
  | CKM_CAMELLIA_MAC
  | CKM_CAMELLIA_MAC_GENERAL
  | CKM_CAMELLIA_CBC_PAD
  | CKM_CAMELLIA_ECB_ENCRYPT_DATA
  | CKM_CAMELLIA_CBC_ENCRYPT_DATA
  | CKM_CAMELLIA_CTR
  | CKM_ARIA_KEY_GEN
  | CKM_ARIA_ECB
  | CKM_ARIA_CBC
  | CKM_ARIA_MAC
  | CKM_ARIA_MAC_GENERAL
  | CKM_ARIA_CBC_PAD
  | CKM_ARIA_ECB_ENCRYPT_DATA
  | CKM_ARIA_CBC_ENCRYPT_DATA
  | CKM_SKIPJACK_KEY_GEN
  | CKM_SKIPJACK_ECB64
  | CKM_SKIPJACK_CBC64
  | CKM_SKIPJACK_OFB64
  | CKM_SKIPJACK_CFB64
  | CKM_SKIPJACK_CFB32
  | CKM_SKIPJACK_CFB16
  | CKM_SKIPJACK_CFB8
  | CKM_SKIPJACK_WRAP
  | CKM_SKIPJACK_PRIVATE_WRAP
  | CKM_SKIPJACK_RELAYX
  | CKM_KEA_KEY_PAIR_GEN
  | CKM_KEA_KEY_DERIVE
  | CKM_FORTEZZA_TIMESTAMP
  | CKM_BATON_KEY_GEN
  | CKM_BATON_ECB128
  | CKM_BATON_ECB96
  | CKM_BATON_CBC128
  | CKM_BATON_COUNTER
  | CKM_BATON_SHUFFLE
  | CKM_BATON_WRAP
  | CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA
  | CKM_ECDSA_SHA1
  | CKM_ECDSA_SHA224
  | CKM_ECDSA_SHA256
  | CKM_ECDSA_SHA384
  | CKM_ECDSA_SHA512
  | CKM_ECDH1_DERIVE
  | CKM_ECDH1_COFACTOR_DERIVE
  | CKM_ECMQV_DERIVE
  | CKM_JUNIPER_KEY_GEN
  | CKM_JUNIPER_ECB128
  | CKM_JUNIPER_CBC128
  | CKM_JUNIPER_COUNTER
  | CKM_JUNIPER_SHUFFLE
  | CKM_JUNIPER_WRAP
  | CKM_FASTHASH
  | CKM_AES_KEY_GEN
  | CKM_AES_ECB
  | CKM_AES_CBC
  | CKM_AES_MAC
  | CKM_AES_MAC_GENERAL
  | CKM_AES_CBC_PAD
  | CKM_AES_CTR
  | CKM_AES_GCM
  | CKM_BLOWFISH_KEY_GEN
  | CKM_BLOWFISH_CBC
  | CKM_TWOFISH_KEY_GEN
  | CKM_TWOFISH_CBC
  | CKM_DES_ECB_ENCRYPT_DATA
  | CKM_DES_CBC_ENCRYPT_DATA
  | CKM_DES3_ECB_ENCRYPT_DATA
  | CKM_DES3_CBC_ENCRYPT_DATA
  | CKM_AES_ECB_ENCRYPT_DATA
  | CKM_AES_CBC_ENCRYPT_DATA
  | CKM_DSA_PARAMETER_GEN
  | CKM_DH_PKCS_PARAMETER_GEN
  | CKM_X9_42_DH_PARAMETER_GEN
  | CKM_GOSTR3410_KEY_PAIR_GEN
  | CKM_GOSTR3410
  | CKM_GOSTR3410_WITH_GOSTR3411
  | CKM_GOSTR3411
  | CKM_GOSTR3411_HMAC
  | CKM_AES_KEY_WRAP
  | CKM_VENDOR_DEFINED
  | CKM_CS_UNKNOWN of P11_ulong.t
  [@@deriving eq,ord,show,yojson]

val to_string : t -> string
val of_string : string -> t

(** The list of all the CKM codes defined above, minus the vendor defined one. *)
val elements : t list
