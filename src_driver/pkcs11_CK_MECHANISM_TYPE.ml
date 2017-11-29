type t = P11_ulong.t
[@@deriving eq,ord,show]

let typ = Ctypes.ulong

let with_value x = Unsigned.ULong.of_string @@ Int64.to_string x

let _CKM_RSA_PKCS_KEY_PAIR_GEN          = with_value 0x00000000L
let _CKM_RSA_PKCS                       = with_value 0x00000001L
let _CKM_RSA_9796                       = with_value 0x00000002L
let _CKM_RSA_X_509                      = with_value 0x00000003L
let _CKM_MD2_RSA_PKCS                   = with_value 0x00000004L
let _CKM_MD5_RSA_PKCS                   = with_value 0x00000005L
let _CKM_SHA1_RSA_PKCS                  = with_value 0x00000006L
let _CKM_RIPEMD128_RSA_PKCS             = with_value 0x00000007L
let _CKM_RIPEMD160_RSA_PKCS             = with_value 0x00000008L
let _CKM_RSA_PKCS_OAEP                  = with_value 0x00000009L
let _CKM_RSA_X9_31_KEY_PAIR_GEN         = with_value 0x0000000AL
let _CKM_RSA_X9_31                      = with_value 0x0000000BL
let _CKM_SHA1_RSA_X9_31                 = with_value 0x0000000CL
let _CKM_RSA_PKCS_PSS                   = with_value 0x0000000DL
let _CKM_SHA1_RSA_PKCS_PSS              = with_value 0x0000000EL
let _CKM_DSA_KEY_PAIR_GEN               = with_value 0x00000010L
let _CKM_DSA                            = with_value 0x00000011L
let _CKM_DSA_SHA1                       = with_value 0x00000012L
let _CKM_DSA_SHA224                     = with_value 0x00000013L
let _CKM_DSA_SHA256                     = with_value 0x00000014L
let _CKM_DSA_SHA384                     = with_value 0x00000015L
let _CKM_DSA_SHA512                     = with_value 0x00000016L
let _CKM_DH_PKCS_KEY_PAIR_GEN           = with_value 0x00000020L
let _CKM_DH_PKCS_DERIVE                 = with_value 0x00000021L
let _CKM_X9_42_DH_KEY_PAIR_GEN          = with_value 0x00000030L
let _CKM_X9_42_DH_DERIVE                = with_value 0x00000031L
let _CKM_X9_42_DH_HYBRID_DERIVE         = with_value 0x00000032L
let _CKM_X9_42_MQV_DERIVE               = with_value 0x00000033L
let _CKM_SHA256_RSA_PKCS                = with_value 0x00000040L
let _CKM_SHA384_RSA_PKCS                = with_value 0x00000041L
let _CKM_SHA512_RSA_PKCS                = with_value 0x00000042L
let _CKM_SHA256_RSA_PKCS_PSS            = with_value 0x00000043L
let _CKM_SHA384_RSA_PKCS_PSS            = with_value 0x00000044L
let _CKM_SHA512_RSA_PKCS_PSS            = with_value 0x00000045L
let _CKM_SHA224_RSA_PKCS                = with_value 0x00000046L
let _CKM_SHA224_RSA_PKCS_PSS            = with_value 0x00000047L
let _CKM_RC2_KEY_GEN                    = with_value 0x00000100L
let _CKM_RC2_ECB                        = with_value 0x00000101L
let _CKM_RC2_CBC                        = with_value 0x00000102L
let _CKM_RC2_MAC                        = with_value 0x00000103L
let _CKM_RC2_MAC_GENERAL                = with_value 0x00000104L
let _CKM_RC2_CBC_PAD                    = with_value 0x00000105L
let _CKM_RC4_KEY_GEN                    = with_value 0x00000110L
let _CKM_RC4                            = with_value 0x00000111L
let _CKM_DES_KEY_GEN                    = with_value 0x00000120L
let _CKM_DES_ECB                        = with_value 0x00000121L
let _CKM_DES_CBC                        = with_value 0x00000122L
let _CKM_DES_MAC                        = with_value 0x00000123L
let _CKM_DES_MAC_GENERAL                = with_value 0x00000124L
let _CKM_DES_CBC_PAD                    = with_value 0x00000125L
let _CKM_DES2_KEY_GEN                   = with_value 0x00000130L
let _CKM_DES3_KEY_GEN                   = with_value 0x00000131L
let _CKM_DES3_ECB                       = with_value 0x00000132L
let _CKM_DES3_CBC                       = with_value 0x00000133L
let _CKM_DES3_MAC                       = with_value 0x00000134L
let _CKM_DES3_MAC_GENERAL               = with_value 0x00000135L
let _CKM_DES3_CBC_PAD                   = with_value 0x00000136L
let _CKM_CDMF_KEY_GEN                   = with_value 0x00000140L
let _CKM_CDMF_ECB                       = with_value 0x00000141L
let _CKM_CDMF_CBC                       = with_value 0x00000142L
let _CKM_CDMF_MAC                       = with_value 0x00000143L
let _CKM_CDMF_MAC_GENERAL               = with_value 0x00000144L
let _CKM_CDMF_CBC_PAD                   = with_value 0x00000145L
let _CKM_DES_OFB64                      = with_value 0x00000150L
let _CKM_DES_OFB8                       = with_value 0x00000151L
let _CKM_DES_CFB64                      = with_value 0x00000152L
let _CKM_DES_CFB8                       = with_value 0x00000153L
let _CKM_MD2                            = with_value 0x00000200L
let _CKM_MD2_HMAC                       = with_value 0x00000201L
let _CKM_MD2_HMAC_GENERAL               = with_value 0x00000202L
let _CKM_MD5                            = with_value 0x00000210L
let _CKM_MD5_HMAC                       = with_value 0x00000211L
let _CKM_MD5_HMAC_GENERAL               = with_value 0x00000212L
let _CKM_SHA_1                          = with_value 0x00000220L
let _CKM_SHA_1_HMAC                     = with_value 0x00000221L
let _CKM_SHA_1_HMAC_GENERAL             = with_value 0x00000222L
let _CKM_RIPEMD128                      = with_value 0x00000230L
let _CKM_RIPEMD128_HMAC                 = with_value 0x00000231L
let _CKM_RIPEMD128_HMAC_GENERAL         = with_value 0x00000232L
let _CKM_RIPEMD160                      = with_value 0x00000240L
let _CKM_RIPEMD160_HMAC                 = with_value 0x00000241L
let _CKM_RIPEMD160_HMAC_GENERAL         = with_value 0x00000242L
let _CKM_SHA256                         = with_value 0x00000250L
let _CKM_SHA256_HMAC                    = with_value 0x00000251L
let _CKM_SHA256_HMAC_GENERAL            = with_value 0x00000252L
let _CKM_SHA224                         = with_value 0x00000255L
let _CKM_SHA224_HMAC                    = with_value 0x00000256L
let _CKM_SHA224_HMAC_GENERAL            = with_value 0x00000257L
let _CKM_SHA384                         = with_value 0x00000260L
let _CKM_SHA384_HMAC                    = with_value 0x00000261L
let _CKM_SHA384_HMAC_GENERAL            = with_value 0x00000262L
let _CKM_SHA512                         = with_value 0x00000270L
let _CKM_SHA512_HMAC                    = with_value 0x00000271L
let _CKM_SHA512_HMAC_GENERAL            = with_value 0x00000272L
let _CKM_SECURID_KEY_GEN                = with_value 0x00000280L
let _CKM_SECURID                        = with_value 0x00000282L
let _CKM_HOTP_KEY_GEN                   = with_value 0x00000290L
let _CKM_HOTP                           = with_value 0x00000291L
let _CKM_ACTI                           = with_value 0x000002A0L
let _CKM_ACTI_KEY_GEN                   = with_value 0x000002A1L
let _CKM_CAST_KEY_GEN                   = with_value 0x00000300L
let _CKM_CAST_ECB                       = with_value 0x00000301L
let _CKM_CAST_CBC                       = with_value 0x00000302L
let _CKM_CAST_MAC                       = with_value 0x00000303L
let _CKM_CAST_MAC_GENERAL               = with_value 0x00000304L
let _CKM_CAST_CBC_PAD                   = with_value 0x00000305L
let _CKM_CAST3_KEY_GEN                  = with_value 0x00000310L
let _CKM_CAST3_ECB                      = with_value 0x00000311L
let _CKM_CAST3_CBC                      = with_value 0x00000312L
let _CKM_CAST3_MAC                      = with_value 0x00000313L
let _CKM_CAST3_MAC_GENERAL              = with_value 0x00000314L
let _CKM_CAST3_CBC_PAD                  = with_value 0x00000315L
let _CKM_CAST128_KEY_GEN                = with_value 0x00000320L
let _CKM_CAST128_ECB                    = with_value 0x00000321L
let _CKM_CAST128_CBC                    = with_value 0x00000322L
let _CKM_CAST128_MAC                    = with_value 0x00000323L
let _CKM_CAST128_MAC_GENERAL            = with_value 0x00000324L
let _CKM_CAST128_CBC_PAD                = with_value 0x00000325L
let _CKM_RC5_KEY_GEN                    = with_value 0x00000330L
let _CKM_RC5_ECB                        = with_value 0x00000331L
let _CKM_RC5_CBC                        = with_value 0x00000332L
let _CKM_RC5_MAC                        = with_value 0x00000333L
let _CKM_RC5_MAC_GENERAL                = with_value 0x00000334L
let _CKM_RC5_CBC_PAD                    = with_value 0x00000335L
let _CKM_IDEA_KEY_GEN                   = with_value 0x00000340L
let _CKM_IDEA_ECB                       = with_value 0x00000341L
let _CKM_IDEA_CBC                       = with_value 0x00000342L
let _CKM_IDEA_MAC                       = with_value 0x00000343L
let _CKM_IDEA_MAC_GENERAL               = with_value 0x00000344L
let _CKM_IDEA_CBC_PAD                   = with_value 0x00000345L
let _CKM_GENERIC_SECRET_KEY_GEN         = with_value 0x00000350L
let _CKM_CONCATENATE_BASE_AND_KEY       = with_value 0x00000360L
let _CKM_CONCATENATE_BASE_AND_DATA      = with_value 0x00000362L
let _CKM_CONCATENATE_DATA_AND_BASE      = with_value 0x00000363L
let _CKM_XOR_BASE_AND_DATA              = with_value 0x00000364L
let _CKM_EXTRACT_KEY_FROM_KEY           = with_value 0x00000365L
let _CKM_SSL3_PRE_MASTER_KEY_GEN        = with_value 0x00000370L
let _CKM_SSL3_MASTER_KEY_DERIVE         = with_value 0x00000371L
let _CKM_SSL3_KEY_AND_MAC_DERIVE        = with_value 0x00000372L
let _CKM_SSL3_MASTER_KEY_DERIVE_DH      = with_value 0x00000373L
let _CKM_TLS_PRE_MASTER_KEY_GEN         = with_value 0x00000374L
let _CKM_TLS_MASTER_KEY_DERIVE          = with_value 0x00000375L
let _CKM_TLS_KEY_AND_MAC_DERIVE         = with_value 0x00000376L
let _CKM_TLS_MASTER_KEY_DERIVE_DH       = with_value 0x00000377L
let _CKM_TLS_PRF                        = with_value 0x00000378L
let _CKM_SSL3_MD5_MAC                   = with_value 0x00000380L
let _CKM_SSL3_SHA1_MAC                  = with_value 0x00000381L
let _CKM_MD5_KEY_DERIVATION             = with_value 0x00000390L
let _CKM_MD2_KEY_DERIVATION             = with_value 0x00000391L
let _CKM_SHA1_KEY_DERIVATION            = with_value 0x00000392L
let _CKM_SHA256_KEY_DERIVATION          = with_value 0x00000393L
let _CKM_SHA384_KEY_DERIVATION          = with_value 0x00000394L
let _CKM_SHA512_KEY_DERIVATION          = with_value 0x00000395L
let _CKM_SHA224_KEY_DERIVATION          = with_value 0x00000396L
let _CKM_PBE_MD2_DES_CBC                = with_value 0x000003A0L
let _CKM_PBE_MD5_DES_CBC                = with_value 0x000003A1L
let _CKM_PBE_MD5_CAST_CBC               = with_value 0x000003A2L
let _CKM_PBE_MD5_CAST3_CBC              = with_value 0x000003A3L
let _CKM_PBE_MD5_CAST128_CBC            = with_value 0x000003A4L
let _CKM_PBE_SHA1_CAST128_CBC           = with_value 0x000003A5L
let _CKM_PBE_SHA1_RC4_128               = with_value 0x000003A6L
let _CKM_PBE_SHA1_RC4_40                = with_value 0x000003A7L
let _CKM_PBE_SHA1_DES3_EDE_CBC          = with_value 0x000003A8L
let _CKM_PBE_SHA1_DES2_EDE_CBC          = with_value 0x000003A9L
let _CKM_PBE_SHA1_RC2_128_CBC           = with_value 0x000003AAL
let _CKM_PBE_SHA1_RC2_40_CBC            = with_value 0x000003ABL
let _CKM_PKCS5_PBKD2                    = with_value 0x000003B0L
let _CKM_PBA_SHA1_WITH_SHA1_HMAC        = with_value 0x000003C0L
let _CKM_WTLS_PRE_MASTER_KEY_GEN        = with_value 0x000003D0L
let _CKM_WTLS_MASTER_KEY_DERIVE         = with_value 0x000003D1L
let _CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC  = with_value 0x000003D2L
let _CKM_WTLS_PRF                       = with_value 0x000003D3L
let _CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = with_value 0x000003D4L
let _CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = with_value 0x000003D5L
let _CKM_KEY_WRAP_LYNKS                 = with_value 0x00000400L
let _CKM_KEY_WRAP_SET_OAEP              = with_value 0x00000401L
let _CKM_CMS_SIG                        = with_value 0x00000500L
let _CKM_KIP_DERIVE                     = with_value 0x00000510L
let _CKM_KIP_WRAP                       = with_value 0x00000511L
let _CKM_KIP_MAC                        = with_value 0x00000512L
let _CKM_CAMELLIA_KEY_GEN               = with_value 0x00000550L
let _CKM_CAMELLIA_ECB                   = with_value 0x00000551L
let _CKM_CAMELLIA_CBC                   = with_value 0x00000552L
let _CKM_CAMELLIA_MAC                   = with_value 0x00000553L
let _CKM_CAMELLIA_MAC_GENERAL           = with_value 0x00000554L
let _CKM_CAMELLIA_CBC_PAD               = with_value 0x00000555L
let _CKM_CAMELLIA_ECB_ENCRYPT_DATA      = with_value 0x00000556L
let _CKM_CAMELLIA_CBC_ENCRYPT_DATA      = with_value 0x00000557L
let _CKM_CAMELLIA_CTR                   = with_value 0x00000558L
let _CKM_ARIA_KEY_GEN                   = with_value 0x00000560L
let _CKM_ARIA_ECB                       = with_value 0x00000561L
let _CKM_ARIA_CBC                       = with_value 0x00000562L
let _CKM_ARIA_MAC                       = with_value 0x00000563L
let _CKM_ARIA_MAC_GENERAL               = with_value 0x00000564L
let _CKM_ARIA_CBC_PAD                   = with_value 0x00000565L
let _CKM_ARIA_ECB_ENCRYPT_DATA          = with_value 0x00000566L
let _CKM_ARIA_CBC_ENCRYPT_DATA          = with_value 0x00000567L
let _CKM_SKIPJACK_KEY_GEN               = with_value 0x00001000L
let _CKM_SKIPJACK_ECB64                 = with_value 0x00001001L
let _CKM_SKIPJACK_CBC64                 = with_value 0x00001002L
let _CKM_SKIPJACK_OFB64                 = with_value 0x00001003L
let _CKM_SKIPJACK_CFB64                 = with_value 0x00001004L
let _CKM_SKIPJACK_CFB32                 = with_value 0x00001005L
let _CKM_SKIPJACK_CFB16                 = with_value 0x00001006L
let _CKM_SKIPJACK_CFB8                  = with_value 0x00001007L
let _CKM_SKIPJACK_WRAP                  = with_value 0x00001008L
let _CKM_SKIPJACK_PRIVATE_WRAP          = with_value 0x00001009L
let _CKM_SKIPJACK_RELAYX                = with_value 0x0000100aL
let _CKM_KEA_KEY_PAIR_GEN               = with_value 0x00001010L
let _CKM_KEA_KEY_DERIVE                 = with_value 0x00001011L
let _CKM_FORTEZZA_TIMESTAMP             = with_value 0x00001020L
let _CKM_BATON_KEY_GEN                  = with_value 0x00001030L
let _CKM_BATON_ECB128                   = with_value 0x00001031L
let _CKM_BATON_ECB96                    = with_value 0x00001032L
let _CKM_BATON_CBC128                   = with_value 0x00001033L
let _CKM_BATON_COUNTER                  = with_value 0x00001034L
let _CKM_BATON_SHUFFLE                  = with_value 0x00001035L
let _CKM_BATON_WRAP                     = with_value 0x00001036L
let _CKM_EC_KEY_PAIR_GEN                = with_value 0x00001040L
let _CKM_ECDSA                          = with_value 0x00001041L
let _CKM_ECDSA_SHA1                     = with_value 0x00001042L
let _CKM_ECDH1_DERIVE                   = with_value 0x00001050L
let _CKM_ECDH1_COFACTOR_DERIVE          = with_value 0x00001051L
let _CKM_ECMQV_DERIVE                   = with_value 0x00001052L
let _CKM_JUNIPER_KEY_GEN                = with_value 0x00001060L
let _CKM_JUNIPER_ECB128                 = with_value 0x00001061L
let _CKM_JUNIPER_CBC128                 = with_value 0x00001062L
let _CKM_JUNIPER_COUNTER                = with_value 0x00001063L
let _CKM_JUNIPER_SHUFFLE                = with_value 0x00001064L
let _CKM_JUNIPER_WRAP                   = with_value 0x00001065L
let _CKM_FASTHASH                       = with_value 0x00001070L
let _CKM_AES_KEY_GEN                    = with_value 0x00001080L
let _CKM_AES_ECB                        = with_value 0x00001081L
let _CKM_AES_CBC                        = with_value 0x00001082L
let _CKM_AES_MAC                        = with_value 0x00001083L
let _CKM_AES_MAC_GENERAL                = with_value 0x00001084L
let _CKM_AES_CBC_PAD                    = with_value 0x00001085L
let _CKM_AES_CTR                        = with_value 0x00001086L
let _CKM_BLOWFISH_KEY_GEN               = with_value 0x00001090L
let _CKM_BLOWFISH_CBC                   = with_value 0x00001091L
let _CKM_TWOFISH_KEY_GEN                = with_value 0x00001092L
let _CKM_TWOFISH_CBC                    = with_value 0x00001093L
let _CKM_DES_ECB_ENCRYPT_DATA           = with_value 0x00001100L
let _CKM_DES_CBC_ENCRYPT_DATA           = with_value 0x00001101L
let _CKM_DES3_ECB_ENCRYPT_DATA          = with_value 0x00001102L
let _CKM_DES3_CBC_ENCRYPT_DATA          = with_value 0x00001103L
let _CKM_AES_ECB_ENCRYPT_DATA           = with_value 0x00001104L
let _CKM_AES_CBC_ENCRYPT_DATA           = with_value 0x00001105L
let _CKM_DSA_PARAMETER_GEN              = with_value 0x00002000L
let _CKM_DH_PKCS_PARAMETER_GEN          = with_value 0x00002001L
let _CKM_X9_42_DH_PARAMETER_GEN         = with_value 0x00002002L
let _CKM_GOSTR3410_KEY_PAIR_GEN         = with_value 0x00001200L
let _CKM_GOSTR3410                      = with_value 0x00001201L
let _CKM_GOSTR3410_WITH_GOSTR3411       = with_value 0x00001202L
let _CKM_GOSTR3411                      = with_value 0x00001210L
let _CKM_GOSTR3411_HMAC                 = with_value 0x00001211L
let _CKM_AES_KEY_WRAP                   = with_value 0x00002109L
let _CKM_VENDOR_DEFINED                 = with_value 0x80000000L


let make u =
  let open P11_mechanism_type in
  match u with
    | CKM_RSA_PKCS_KEY_PAIR_GEN  -> _CKM_RSA_PKCS_KEY_PAIR_GEN
    | CKM_RSA_PKCS  -> _CKM_RSA_PKCS
    | CKM_RSA_9796  -> _CKM_RSA_9796
    | CKM_RSA_X_509  -> _CKM_RSA_X_509
    | CKM_MD2_RSA_PKCS  -> _CKM_MD2_RSA_PKCS
    | CKM_MD5_RSA_PKCS  -> _CKM_MD5_RSA_PKCS
    | CKM_SHA1_RSA_PKCS  -> _CKM_SHA1_RSA_PKCS
    | CKM_RIPEMD128_RSA_PKCS  -> _CKM_RIPEMD128_RSA_PKCS
    | CKM_RIPEMD160_RSA_PKCS  -> _CKM_RIPEMD160_RSA_PKCS
    | CKM_RSA_PKCS_OAEP  -> _CKM_RSA_PKCS_OAEP
    | CKM_RSA_X9_31_KEY_PAIR_GEN  -> _CKM_RSA_X9_31_KEY_PAIR_GEN
    | CKM_RSA_X9_31  -> _CKM_RSA_X9_31
    | CKM_SHA1_RSA_X9_31  -> _CKM_SHA1_RSA_X9_31
    | CKM_RSA_PKCS_PSS  -> _CKM_RSA_PKCS_PSS
    | CKM_SHA1_RSA_PKCS_PSS  -> _CKM_SHA1_RSA_PKCS_PSS
    | CKM_DSA_KEY_PAIR_GEN  -> _CKM_DSA_KEY_PAIR_GEN
    | CKM_DSA  -> _CKM_DSA
    | CKM_DSA_SHA1 -> _CKM_DSA_SHA1
    | CKM_DSA_SHA224 -> _CKM_DSA_SHA224
    | CKM_DSA_SHA256 -> _CKM_DSA_SHA256
    | CKM_DSA_SHA384 -> _CKM_DSA_SHA384
    | CKM_DSA_SHA512 -> _CKM_DSA_SHA512
    | CKM_DH_PKCS_KEY_PAIR_GEN  -> _CKM_DH_PKCS_KEY_PAIR_GEN
    | CKM_DH_PKCS_DERIVE  -> _CKM_DH_PKCS_DERIVE
    | CKM_X9_42_DH_KEY_PAIR_GEN  -> _CKM_X9_42_DH_KEY_PAIR_GEN
    | CKM_X9_42_DH_DERIVE  -> _CKM_X9_42_DH_DERIVE
    | CKM_X9_42_DH_HYBRID_DERIVE  -> _CKM_X9_42_DH_HYBRID_DERIVE
    | CKM_X9_42_MQV_DERIVE  -> _CKM_X9_42_MQV_DERIVE
    | CKM_SHA256_RSA_PKCS  -> _CKM_SHA256_RSA_PKCS
    | CKM_SHA384_RSA_PKCS  -> _CKM_SHA384_RSA_PKCS
    | CKM_SHA512_RSA_PKCS  -> _CKM_SHA512_RSA_PKCS
    | CKM_SHA256_RSA_PKCS_PSS  -> _CKM_SHA256_RSA_PKCS_PSS
    | CKM_SHA384_RSA_PKCS_PSS  -> _CKM_SHA384_RSA_PKCS_PSS
    | CKM_SHA512_RSA_PKCS_PSS  -> _CKM_SHA512_RSA_PKCS_PSS
    | CKM_SHA224_RSA_PKCS  -> _CKM_SHA224_RSA_PKCS
    | CKM_SHA224_RSA_PKCS_PSS  -> _CKM_SHA224_RSA_PKCS_PSS
    | CKM_RC2_KEY_GEN  -> _CKM_RC2_KEY_GEN
    | CKM_RC2_ECB  -> _CKM_RC2_ECB
    | CKM_RC2_CBC  -> _CKM_RC2_CBC
    | CKM_RC2_MAC  -> _CKM_RC2_MAC
    | CKM_RC2_MAC_GENERAL  -> _CKM_RC2_MAC_GENERAL
    | CKM_RC2_CBC_PAD  -> _CKM_RC2_CBC_PAD
    | CKM_RC4_KEY_GEN  -> _CKM_RC4_KEY_GEN
    | CKM_RC4  -> _CKM_RC4
    | CKM_DES_KEY_GEN  -> _CKM_DES_KEY_GEN
    | CKM_DES_ECB  -> _CKM_DES_ECB
    | CKM_DES_CBC  -> _CKM_DES_CBC
    | CKM_DES_MAC  -> _CKM_DES_MAC
    | CKM_DES_MAC_GENERAL  -> _CKM_DES_MAC_GENERAL
    | CKM_DES_CBC_PAD  -> _CKM_DES_CBC_PAD
    | CKM_DES2_KEY_GEN  -> _CKM_DES2_KEY_GEN
    | CKM_DES3_KEY_GEN  -> _CKM_DES3_KEY_GEN
    | CKM_DES3_ECB  -> _CKM_DES3_ECB
    | CKM_DES3_CBC  -> _CKM_DES3_CBC
    | CKM_DES3_MAC  -> _CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL  -> _CKM_DES3_MAC_GENERAL
    | CKM_DES3_CBC_PAD  -> _CKM_DES3_CBC_PAD
    | CKM_CDMF_KEY_GEN  -> _CKM_CDMF_KEY_GEN
    | CKM_CDMF_ECB  -> _CKM_CDMF_ECB
    | CKM_CDMF_CBC  -> _CKM_CDMF_CBC
    | CKM_CDMF_MAC  -> _CKM_CDMF_MAC
    | CKM_CDMF_MAC_GENERAL  -> _CKM_CDMF_MAC_GENERAL
    | CKM_CDMF_CBC_PAD  -> _CKM_CDMF_CBC_PAD
    | CKM_DES_OFB64  -> _CKM_DES_OFB64
    | CKM_DES_OFB8  -> _CKM_DES_OFB8
    | CKM_DES_CFB64  -> _CKM_DES_CFB64
    | CKM_DES_CFB8  -> _CKM_DES_CFB8
    | CKM_MD2  -> _CKM_MD2
    | CKM_MD2_HMAC  -> _CKM_MD2_HMAC
    | CKM_MD2_HMAC_GENERAL  -> _CKM_MD2_HMAC_GENERAL
    | CKM_MD5  -> _CKM_MD5
    | CKM_MD5_HMAC  -> _CKM_MD5_HMAC
    | CKM_MD5_HMAC_GENERAL  -> _CKM_MD5_HMAC_GENERAL
    | CKM_SHA_1  -> _CKM_SHA_1
    | CKM_SHA_1_HMAC  -> _CKM_SHA_1_HMAC
    | CKM_SHA_1_HMAC_GENERAL  -> _CKM_SHA_1_HMAC_GENERAL
    | CKM_RIPEMD128  -> _CKM_RIPEMD128
    | CKM_RIPEMD128_HMAC  -> _CKM_RIPEMD128_HMAC
    | CKM_RIPEMD128_HMAC_GENERAL  -> _CKM_RIPEMD128_HMAC_GENERAL
    | CKM_RIPEMD160  -> _CKM_RIPEMD160
    | CKM_RIPEMD160_HMAC  -> _CKM_RIPEMD160_HMAC
    | CKM_RIPEMD160_HMAC_GENERAL  -> _CKM_RIPEMD160_HMAC_GENERAL
    | CKM_SHA256  -> _CKM_SHA256
    | CKM_SHA256_HMAC  -> _CKM_SHA256_HMAC
    | CKM_SHA256_HMAC_GENERAL  -> _CKM_SHA256_HMAC_GENERAL
    | CKM_SHA224  -> _CKM_SHA224
    | CKM_SHA224_HMAC  -> _CKM_SHA224_HMAC
    | CKM_SHA224_HMAC_GENERAL  -> _CKM_SHA224_HMAC_GENERAL
    | CKM_SHA384  -> _CKM_SHA384
    | CKM_SHA384_HMAC  -> _CKM_SHA384_HMAC
    | CKM_SHA384_HMAC_GENERAL  -> _CKM_SHA384_HMAC_GENERAL
    | CKM_SHA512  -> _CKM_SHA512
    | CKM_SHA512_HMAC  -> _CKM_SHA512_HMAC
    | CKM_SHA512_HMAC_GENERAL  -> _CKM_SHA512_HMAC_GENERAL
    | CKM_SECURID_KEY_GEN  -> _CKM_SECURID_KEY_GEN
    | CKM_SECURID  -> _CKM_SECURID
    | CKM_HOTP_KEY_GEN  -> _CKM_HOTP_KEY_GEN
    | CKM_HOTP  -> _CKM_HOTP
    | CKM_ACTI  -> _CKM_ACTI
    | CKM_ACTI_KEY_GEN  -> _CKM_ACTI_KEY_GEN
    | CKM_CAST_KEY_GEN  -> _CKM_CAST_KEY_GEN
    | CKM_CAST_ECB  -> _CKM_CAST_ECB
    | CKM_CAST_CBC  -> _CKM_CAST_CBC
    | CKM_CAST_MAC  -> _CKM_CAST_MAC
    | CKM_CAST_MAC_GENERAL  -> _CKM_CAST_MAC_GENERAL
    | CKM_CAST_CBC_PAD  -> _CKM_CAST_CBC_PAD
    | CKM_CAST3_KEY_GEN  -> _CKM_CAST3_KEY_GEN
    | CKM_CAST3_ECB  -> _CKM_CAST3_ECB
    | CKM_CAST3_CBC  -> _CKM_CAST3_CBC
    | CKM_CAST3_MAC  -> _CKM_CAST3_MAC
    | CKM_CAST3_MAC_GENERAL  -> _CKM_CAST3_MAC_GENERAL
    | CKM_CAST3_CBC_PAD  -> _CKM_CAST3_CBC_PAD
    | CKM_CAST128_KEY_GEN  -> _CKM_CAST128_KEY_GEN
    | CKM_CAST128_ECB  -> _CKM_CAST128_ECB
    | CKM_CAST128_CBC  -> _CKM_CAST128_CBC
    | CKM_CAST128_MAC  -> _CKM_CAST128_MAC
    | CKM_CAST128_MAC_GENERAL  -> _CKM_CAST128_MAC_GENERAL
    | CKM_CAST128_CBC_PAD  -> _CKM_CAST128_CBC_PAD
    | CKM_RC5_KEY_GEN  -> _CKM_RC5_KEY_GEN
    | CKM_RC5_ECB  -> _CKM_RC5_ECB
    | CKM_RC5_CBC  -> _CKM_RC5_CBC
    | CKM_RC5_MAC  -> _CKM_RC5_MAC
    | CKM_RC5_MAC_GENERAL  -> _CKM_RC5_MAC_GENERAL
    | CKM_RC5_CBC_PAD  -> _CKM_RC5_CBC_PAD
    | CKM_IDEA_KEY_GEN  -> _CKM_IDEA_KEY_GEN
    | CKM_IDEA_ECB  -> _CKM_IDEA_ECB
    | CKM_IDEA_CBC  -> _CKM_IDEA_CBC
    | CKM_IDEA_MAC  -> _CKM_IDEA_MAC
    | CKM_IDEA_MAC_GENERAL  -> _CKM_IDEA_MAC_GENERAL
    | CKM_IDEA_CBC_PAD  -> _CKM_IDEA_CBC_PAD
    | CKM_GENERIC_SECRET_KEY_GEN  -> _CKM_GENERIC_SECRET_KEY_GEN
    | CKM_CONCATENATE_BASE_AND_KEY  -> _CKM_CONCATENATE_BASE_AND_KEY
    | CKM_CONCATENATE_BASE_AND_DATA  -> _CKM_CONCATENATE_BASE_AND_DATA
    | CKM_CONCATENATE_DATA_AND_BASE  -> _CKM_CONCATENATE_DATA_AND_BASE
    | CKM_XOR_BASE_AND_DATA  -> _CKM_XOR_BASE_AND_DATA
    | CKM_EXTRACT_KEY_FROM_KEY  -> _CKM_EXTRACT_KEY_FROM_KEY
    | CKM_SSL3_PRE_MASTER_KEY_GEN  -> _CKM_SSL3_PRE_MASTER_KEY_GEN
    | CKM_SSL3_MASTER_KEY_DERIVE  -> _CKM_SSL3_MASTER_KEY_DERIVE
    | CKM_SSL3_KEY_AND_MAC_DERIVE  -> _CKM_SSL3_KEY_AND_MAC_DERIVE
    | CKM_SSL3_MASTER_KEY_DERIVE_DH  -> _CKM_SSL3_MASTER_KEY_DERIVE_DH
    | CKM_TLS_PRE_MASTER_KEY_GEN  -> _CKM_TLS_PRE_MASTER_KEY_GEN
    | CKM_TLS_MASTER_KEY_DERIVE  -> _CKM_TLS_MASTER_KEY_DERIVE
    | CKM_TLS_KEY_AND_MAC_DERIVE  -> _CKM_TLS_KEY_AND_MAC_DERIVE
    | CKM_TLS_MASTER_KEY_DERIVE_DH  -> _CKM_TLS_MASTER_KEY_DERIVE_DH
    | CKM_TLS_PRF  -> _CKM_TLS_PRF
    | CKM_SSL3_MD5_MAC  -> _CKM_SSL3_MD5_MAC
    | CKM_SSL3_SHA1_MAC  -> _CKM_SSL3_SHA1_MAC
    | CKM_MD5_KEY_DERIVATION  -> _CKM_MD5_KEY_DERIVATION
    | CKM_MD2_KEY_DERIVATION  -> _CKM_MD2_KEY_DERIVATION
    | CKM_SHA1_KEY_DERIVATION  -> _CKM_SHA1_KEY_DERIVATION
    | CKM_SHA256_KEY_DERIVATION  -> _CKM_SHA256_KEY_DERIVATION
    | CKM_SHA384_KEY_DERIVATION  -> _CKM_SHA384_KEY_DERIVATION
    | CKM_SHA512_KEY_DERIVATION  -> _CKM_SHA512_KEY_DERIVATION
    | CKM_SHA224_KEY_DERIVATION  -> _CKM_SHA224_KEY_DERIVATION
    | CKM_PBE_MD2_DES_CBC  -> _CKM_PBE_MD2_DES_CBC
    | CKM_PBE_MD5_DES_CBC  -> _CKM_PBE_MD5_DES_CBC
    | CKM_PBE_MD5_CAST_CBC  -> _CKM_PBE_MD5_CAST_CBC
    | CKM_PBE_MD5_CAST3_CBC  -> _CKM_PBE_MD5_CAST3_CBC
    | CKM_PBE_MD5_CAST128_CBC  -> _CKM_PBE_MD5_CAST128_CBC
    | CKM_PBE_SHA1_CAST128_CBC  -> _CKM_PBE_SHA1_CAST128_CBC
    | CKM_PBE_SHA1_RC4_128  -> _CKM_PBE_SHA1_RC4_128
    | CKM_PBE_SHA1_RC4_40  -> _CKM_PBE_SHA1_RC4_40
    | CKM_PBE_SHA1_DES3_EDE_CBC  -> _CKM_PBE_SHA1_DES3_EDE_CBC
    | CKM_PBE_SHA1_DES2_EDE_CBC  -> _CKM_PBE_SHA1_DES2_EDE_CBC
    | CKM_PBE_SHA1_RC2_128_CBC  -> _CKM_PBE_SHA1_RC2_128_CBC
    | CKM_PBE_SHA1_RC2_40_CBC  -> _CKM_PBE_SHA1_RC2_40_CBC
    | CKM_PKCS5_PBKD2  -> _CKM_PKCS5_PBKD2
    | CKM_PBA_SHA1_WITH_SHA1_HMAC  -> _CKM_PBA_SHA1_WITH_SHA1_HMAC
    | CKM_WTLS_PRE_MASTER_KEY_GEN  -> _CKM_WTLS_PRE_MASTER_KEY_GEN
    | CKM_WTLS_MASTER_KEY_DERIVE  -> _CKM_WTLS_MASTER_KEY_DERIVE
    | CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC  -> _CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
    | CKM_WTLS_PRF  -> _CKM_WTLS_PRF
    | CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  -> _CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
    | CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  -> _CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
    | CKM_KEY_WRAP_LYNKS  -> _CKM_KEY_WRAP_LYNKS
    | CKM_KEY_WRAP_SET_OAEP  -> _CKM_KEY_WRAP_SET_OAEP
    | CKM_CMS_SIG  -> _CKM_CMS_SIG
    | CKM_KIP_DERIVE  -> _CKM_KIP_DERIVE
    | CKM_KIP_WRAP  -> _CKM_KIP_WRAP
    | CKM_KIP_MAC  -> _CKM_KIP_MAC
    | CKM_CAMELLIA_KEY_GEN  -> _CKM_CAMELLIA_KEY_GEN
    | CKM_CAMELLIA_ECB  -> _CKM_CAMELLIA_ECB
    | CKM_CAMELLIA_CBC  -> _CKM_CAMELLIA_CBC
    | CKM_CAMELLIA_MAC  -> _CKM_CAMELLIA_MAC
    | CKM_CAMELLIA_MAC_GENERAL  -> _CKM_CAMELLIA_MAC_GENERAL
    | CKM_CAMELLIA_CBC_PAD  -> _CKM_CAMELLIA_CBC_PAD
    | CKM_CAMELLIA_ECB_ENCRYPT_DATA  -> _CKM_CAMELLIA_ECB_ENCRYPT_DATA
    | CKM_CAMELLIA_CBC_ENCRYPT_DATA  -> _CKM_CAMELLIA_CBC_ENCRYPT_DATA
    | CKM_CAMELLIA_CTR  -> _CKM_CAMELLIA_CTR
    | CKM_ARIA_KEY_GEN  -> _CKM_ARIA_KEY_GEN
    | CKM_ARIA_ECB  -> _CKM_ARIA_ECB
    | CKM_ARIA_CBC  -> _CKM_ARIA_CBC
    | CKM_ARIA_MAC  -> _CKM_ARIA_MAC
    | CKM_ARIA_MAC_GENERAL  -> _CKM_ARIA_MAC_GENERAL
    | CKM_ARIA_CBC_PAD  -> _CKM_ARIA_CBC_PAD
    | CKM_ARIA_ECB_ENCRYPT_DATA  -> _CKM_ARIA_ECB_ENCRYPT_DATA
    | CKM_ARIA_CBC_ENCRYPT_DATA  -> _CKM_ARIA_CBC_ENCRYPT_DATA
    | CKM_SKIPJACK_KEY_GEN  -> _CKM_SKIPJACK_KEY_GEN
    | CKM_SKIPJACK_ECB64  -> _CKM_SKIPJACK_ECB64
    | CKM_SKIPJACK_CBC64  -> _CKM_SKIPJACK_CBC64
    | CKM_SKIPJACK_OFB64  -> _CKM_SKIPJACK_OFB64
    | CKM_SKIPJACK_CFB64  -> _CKM_SKIPJACK_CFB64
    | CKM_SKIPJACK_CFB32  -> _CKM_SKIPJACK_CFB32
    | CKM_SKIPJACK_CFB16  -> _CKM_SKIPJACK_CFB16
    | CKM_SKIPJACK_CFB8  -> _CKM_SKIPJACK_CFB8
    | CKM_SKIPJACK_WRAP  -> _CKM_SKIPJACK_WRAP
    | CKM_SKIPJACK_PRIVATE_WRAP  -> _CKM_SKIPJACK_PRIVATE_WRAP
    | CKM_SKIPJACK_RELAYX  -> _CKM_SKIPJACK_RELAYX
    | CKM_KEA_KEY_PAIR_GEN  -> _CKM_KEA_KEY_PAIR_GEN
    | CKM_KEA_KEY_DERIVE  -> _CKM_KEA_KEY_DERIVE
    | CKM_FORTEZZA_TIMESTAMP  -> _CKM_FORTEZZA_TIMESTAMP
    | CKM_BATON_KEY_GEN  -> _CKM_BATON_KEY_GEN
    | CKM_BATON_ECB128  -> _CKM_BATON_ECB128
    | CKM_BATON_ECB96  -> _CKM_BATON_ECB96
    | CKM_BATON_CBC128  -> _CKM_BATON_CBC128
    | CKM_BATON_COUNTER  -> _CKM_BATON_COUNTER
    | CKM_BATON_SHUFFLE  -> _CKM_BATON_SHUFFLE
    | CKM_BATON_WRAP  -> _CKM_BATON_WRAP
    | CKM_EC_KEY_PAIR_GEN  -> _CKM_EC_KEY_PAIR_GEN
    | CKM_ECDSA  -> _CKM_ECDSA
    | CKM_ECDSA_SHA1  -> _CKM_ECDSA_SHA1
    | CKM_ECDH1_DERIVE  -> _CKM_ECDH1_DERIVE
    | CKM_ECDH1_COFACTOR_DERIVE  -> _CKM_ECDH1_COFACTOR_DERIVE
    | CKM_ECMQV_DERIVE  -> _CKM_ECMQV_DERIVE
    | CKM_JUNIPER_KEY_GEN  -> _CKM_JUNIPER_KEY_GEN
    | CKM_JUNIPER_ECB128  -> _CKM_JUNIPER_ECB128
    | CKM_JUNIPER_CBC128  -> _CKM_JUNIPER_CBC128
    | CKM_JUNIPER_COUNTER  -> _CKM_JUNIPER_COUNTER
    | CKM_JUNIPER_SHUFFLE  -> _CKM_JUNIPER_SHUFFLE
    | CKM_JUNIPER_WRAP  -> _CKM_JUNIPER_WRAP
    | CKM_FASTHASH  -> _CKM_FASTHASH
    | CKM_AES_KEY_GEN  -> _CKM_AES_KEY_GEN
    | CKM_AES_ECB  -> _CKM_AES_ECB
    | CKM_AES_CBC  -> _CKM_AES_CBC
    | CKM_AES_MAC  -> _CKM_AES_MAC
    | CKM_AES_MAC_GENERAL  -> _CKM_AES_MAC_GENERAL
    | CKM_AES_CBC_PAD  -> _CKM_AES_CBC_PAD
    | CKM_AES_CTR  -> _CKM_AES_CTR
    | CKM_BLOWFISH_KEY_GEN  -> _CKM_BLOWFISH_KEY_GEN
    | CKM_BLOWFISH_CBC  -> _CKM_BLOWFISH_CBC
    | CKM_TWOFISH_KEY_GEN  -> _CKM_TWOFISH_KEY_GEN
    | CKM_TWOFISH_CBC  -> _CKM_TWOFISH_CBC
    | CKM_DES_ECB_ENCRYPT_DATA  -> _CKM_DES_ECB_ENCRYPT_DATA
    | CKM_DES_CBC_ENCRYPT_DATA  -> _CKM_DES_CBC_ENCRYPT_DATA
    | CKM_DES3_ECB_ENCRYPT_DATA  -> _CKM_DES3_ECB_ENCRYPT_DATA
    | CKM_DES3_CBC_ENCRYPT_DATA  -> _CKM_DES3_CBC_ENCRYPT_DATA
    | CKM_AES_ECB_ENCRYPT_DATA  -> _CKM_AES_ECB_ENCRYPT_DATA
    | CKM_AES_CBC_ENCRYPT_DATA  -> _CKM_AES_CBC_ENCRYPT_DATA
    | CKM_DSA_PARAMETER_GEN  -> _CKM_DSA_PARAMETER_GEN
    | CKM_DH_PKCS_PARAMETER_GEN  -> _CKM_DH_PKCS_PARAMETER_GEN
    | CKM_X9_42_DH_PARAMETER_GEN  -> _CKM_X9_42_DH_PARAMETER_GEN
    | CKM_GOSTR3410_KEY_PAIR_GEN -> _CKM_GOSTR3410_KEY_PAIR_GEN
    | CKM_GOSTR3410 -> _CKM_GOSTR3410
    | CKM_GOSTR3410_WITH_GOSTR3411 -> _CKM_GOSTR3410_WITH_GOSTR3411
    | CKM_GOSTR3411 -> _CKM_GOSTR3411
    | CKM_GOSTR3411_HMAC -> _CKM_GOSTR3411_HMAC
    | CKM_AES_KEY_WRAP -> _CKM_AES_KEY_WRAP
    | CKM_VENDOR_DEFINED  -> _CKM_VENDOR_DEFINED
    | CKM_CS_UNKNOWN x -> x

let view t =
  let open P11_mechanism_type in
  let is value = Unsigned.ULong.compare t value = 0 in
  match () with
    | _ when is _CKM_RSA_PKCS_KEY_PAIR_GEN -> CKM_RSA_PKCS_KEY_PAIR_GEN
    | _ when is _CKM_RSA_PKCS -> CKM_RSA_PKCS
    | _ when is _CKM_RSA_9796 -> CKM_RSA_9796
    | _ when is _CKM_RSA_X_509 -> CKM_RSA_X_509
    | _ when is _CKM_MD2_RSA_PKCS -> CKM_MD2_RSA_PKCS
    | _ when is _CKM_MD5_RSA_PKCS -> CKM_MD5_RSA_PKCS
    | _ when is _CKM_SHA1_RSA_PKCS -> CKM_SHA1_RSA_PKCS
    | _ when is _CKM_RIPEMD128_RSA_PKCS -> CKM_RIPEMD128_RSA_PKCS
    | _ when is _CKM_RIPEMD160_RSA_PKCS -> CKM_RIPEMD160_RSA_PKCS
    | _ when is _CKM_RSA_PKCS_OAEP -> CKM_RSA_PKCS_OAEP
    | _ when is _CKM_RSA_X9_31_KEY_PAIR_GEN -> CKM_RSA_X9_31_KEY_PAIR_GEN
    | _ when is _CKM_RSA_X9_31 -> CKM_RSA_X9_31
    | _ when is _CKM_SHA1_RSA_X9_31 -> CKM_SHA1_RSA_X9_31
    | _ when is _CKM_RSA_PKCS_PSS -> CKM_RSA_PKCS_PSS
    | _ when is _CKM_SHA1_RSA_PKCS_PSS -> CKM_SHA1_RSA_PKCS_PSS
    | _ when is _CKM_DSA_KEY_PAIR_GEN -> CKM_DSA_KEY_PAIR_GEN
    | _ when is _CKM_DSA -> CKM_DSA
    | _ when is _CKM_DSA_SHA1 -> CKM_DSA_SHA1
    | _ when is _CKM_DSA_SHA224 -> CKM_DSA_SHA224
    | _ when is _CKM_DSA_SHA256 -> CKM_DSA_SHA256
    | _ when is _CKM_DSA_SHA384 -> CKM_DSA_SHA384
    | _ when is _CKM_DSA_SHA512 -> CKM_DSA_SHA512
    | _ when is _CKM_DH_PKCS_KEY_PAIR_GEN -> CKM_DH_PKCS_KEY_PAIR_GEN
    | _ when is _CKM_DH_PKCS_DERIVE -> CKM_DH_PKCS_DERIVE
    | _ when is _CKM_X9_42_DH_KEY_PAIR_GEN -> CKM_X9_42_DH_KEY_PAIR_GEN
    | _ when is _CKM_X9_42_DH_DERIVE -> CKM_X9_42_DH_DERIVE
    | _ when is _CKM_X9_42_DH_HYBRID_DERIVE -> CKM_X9_42_DH_HYBRID_DERIVE
    | _ when is _CKM_X9_42_MQV_DERIVE -> CKM_X9_42_MQV_DERIVE
    | _ when is _CKM_SHA256_RSA_PKCS -> CKM_SHA256_RSA_PKCS
    | _ when is _CKM_SHA384_RSA_PKCS -> CKM_SHA384_RSA_PKCS
    | _ when is _CKM_SHA512_RSA_PKCS -> CKM_SHA512_RSA_PKCS
    | _ when is _CKM_SHA256_RSA_PKCS_PSS -> CKM_SHA256_RSA_PKCS_PSS
    | _ when is _CKM_SHA384_RSA_PKCS_PSS -> CKM_SHA384_RSA_PKCS_PSS
    | _ when is _CKM_SHA512_RSA_PKCS_PSS -> CKM_SHA512_RSA_PKCS_PSS
    | _ when is _CKM_SHA224_RSA_PKCS -> CKM_SHA224_RSA_PKCS
    | _ when is _CKM_SHA224_RSA_PKCS_PSS -> CKM_SHA224_RSA_PKCS_PSS
    | _ when is _CKM_RC2_KEY_GEN -> CKM_RC2_KEY_GEN
    | _ when is _CKM_RC2_ECB -> CKM_RC2_ECB
    | _ when is _CKM_RC2_CBC -> CKM_RC2_CBC
    | _ when is _CKM_RC2_MAC -> CKM_RC2_MAC
    | _ when is _CKM_RC2_MAC_GENERAL -> CKM_RC2_MAC_GENERAL
    | _ when is _CKM_RC2_CBC_PAD -> CKM_RC2_CBC_PAD
    | _ when is _CKM_RC4_KEY_GEN -> CKM_RC4_KEY_GEN
    | _ when is _CKM_RC4 -> CKM_RC4
    | _ when is _CKM_DES_KEY_GEN -> CKM_DES_KEY_GEN
    | _ when is _CKM_DES_ECB -> CKM_DES_ECB
    | _ when is _CKM_DES_CBC -> CKM_DES_CBC
    | _ when is _CKM_DES_MAC -> CKM_DES_MAC
    | _ when is _CKM_DES_MAC_GENERAL -> CKM_DES_MAC_GENERAL
    | _ when is _CKM_DES_CBC_PAD -> CKM_DES_CBC_PAD
    | _ when is _CKM_DES2_KEY_GEN -> CKM_DES2_KEY_GEN
    | _ when is _CKM_DES3_KEY_GEN -> CKM_DES3_KEY_GEN
    | _ when is _CKM_DES3_ECB -> CKM_DES3_ECB
    | _ when is _CKM_DES3_CBC -> CKM_DES3_CBC
    | _ when is _CKM_DES3_MAC -> CKM_DES3_MAC
    | _ when is _CKM_DES3_MAC_GENERAL -> CKM_DES3_MAC_GENERAL
    | _ when is _CKM_DES3_CBC_PAD -> CKM_DES3_CBC_PAD
    | _ when is _CKM_CDMF_KEY_GEN -> CKM_CDMF_KEY_GEN
    | _ when is _CKM_CDMF_ECB -> CKM_CDMF_ECB
    | _ when is _CKM_CDMF_CBC -> CKM_CDMF_CBC
    | _ when is _CKM_CDMF_MAC -> CKM_CDMF_MAC
    | _ when is _CKM_CDMF_MAC_GENERAL -> CKM_CDMF_MAC_GENERAL
    | _ when is _CKM_CDMF_CBC_PAD -> CKM_CDMF_CBC_PAD
    | _ when is _CKM_DES_OFB64 -> CKM_DES_OFB64
    | _ when is _CKM_DES_OFB8 -> CKM_DES_OFB8
    | _ when is _CKM_DES_CFB64 -> CKM_DES_CFB64
    | _ when is _CKM_DES_CFB8 -> CKM_DES_CFB8
    | _ when is _CKM_MD2 -> CKM_MD2
    | _ when is _CKM_MD2_HMAC -> CKM_MD2_HMAC
    | _ when is _CKM_MD2_HMAC_GENERAL -> CKM_MD2_HMAC_GENERAL
    | _ when is _CKM_MD5 -> CKM_MD5
    | _ when is _CKM_MD5_HMAC -> CKM_MD5_HMAC
    | _ when is _CKM_MD5_HMAC_GENERAL -> CKM_MD5_HMAC_GENERAL
    | _ when is _CKM_SHA_1 -> CKM_SHA_1
    | _ when is _CKM_SHA_1_HMAC -> CKM_SHA_1_HMAC
    | _ when is _CKM_SHA_1_HMAC_GENERAL -> CKM_SHA_1_HMAC_GENERAL
    | _ when is _CKM_RIPEMD128 -> CKM_RIPEMD128
    | _ when is _CKM_RIPEMD128_HMAC -> CKM_RIPEMD128_HMAC
    | _ when is _CKM_RIPEMD128_HMAC_GENERAL -> CKM_RIPEMD128_HMAC_GENERAL
    | _ when is _CKM_RIPEMD160 -> CKM_RIPEMD160
    | _ when is _CKM_RIPEMD160_HMAC -> CKM_RIPEMD160_HMAC
    | _ when is _CKM_RIPEMD160_HMAC_GENERAL -> CKM_RIPEMD160_HMAC_GENERAL
    | _ when is _CKM_SHA256 -> CKM_SHA256
    | _ when is _CKM_SHA256_HMAC -> CKM_SHA256_HMAC
    | _ when is _CKM_SHA256_HMAC_GENERAL -> CKM_SHA256_HMAC_GENERAL
    | _ when is _CKM_SHA224 -> CKM_SHA224
    | _ when is _CKM_SHA224_HMAC -> CKM_SHA224_HMAC
    | _ when is _CKM_SHA224_HMAC_GENERAL -> CKM_SHA224_HMAC_GENERAL
    | _ when is _CKM_SHA384 -> CKM_SHA384
    | _ when is _CKM_SHA384_HMAC -> CKM_SHA384_HMAC
    | _ when is _CKM_SHA384_HMAC_GENERAL -> CKM_SHA384_HMAC_GENERAL
    | _ when is _CKM_SHA512 -> CKM_SHA512
    | _ when is _CKM_SHA512_HMAC -> CKM_SHA512_HMAC
    | _ when is _CKM_SHA512_HMAC_GENERAL -> CKM_SHA512_HMAC_GENERAL
    | _ when is _CKM_SECURID_KEY_GEN -> CKM_SECURID_KEY_GEN
    | _ when is _CKM_SECURID -> CKM_SECURID
    | _ when is _CKM_HOTP_KEY_GEN -> CKM_HOTP_KEY_GEN
    | _ when is _CKM_HOTP -> CKM_HOTP
    | _ when is _CKM_ACTI -> CKM_ACTI
    | _ when is _CKM_ACTI_KEY_GEN -> CKM_ACTI_KEY_GEN
    | _ when is _CKM_CAST_KEY_GEN -> CKM_CAST_KEY_GEN
    | _ when is _CKM_CAST_ECB -> CKM_CAST_ECB
    | _ when is _CKM_CAST_CBC -> CKM_CAST_CBC
    | _ when is _CKM_CAST_MAC -> CKM_CAST_MAC
    | _ when is _CKM_CAST_MAC_GENERAL -> CKM_CAST_MAC_GENERAL
    | _ when is _CKM_CAST_CBC_PAD -> CKM_CAST_CBC_PAD
    | _ when is _CKM_CAST3_KEY_GEN -> CKM_CAST3_KEY_GEN
    | _ when is _CKM_CAST3_ECB -> CKM_CAST3_ECB
    | _ when is _CKM_CAST3_CBC -> CKM_CAST3_CBC
    | _ when is _CKM_CAST3_MAC -> CKM_CAST3_MAC
    | _ when is _CKM_CAST3_MAC_GENERAL -> CKM_CAST3_MAC_GENERAL
    | _ when is _CKM_CAST3_CBC_PAD -> CKM_CAST3_CBC_PAD
    | _ when is _CKM_CAST128_KEY_GEN -> CKM_CAST128_KEY_GEN
    | _ when is _CKM_CAST128_ECB -> CKM_CAST128_ECB
    | _ when is _CKM_CAST128_CBC -> CKM_CAST128_CBC
    | _ when is _CKM_CAST128_MAC -> CKM_CAST128_MAC
    | _ when is _CKM_CAST128_MAC_GENERAL -> CKM_CAST128_MAC_GENERAL
    | _ when is _CKM_CAST128_CBC_PAD -> CKM_CAST128_CBC_PAD
    | _ when is _CKM_RC5_KEY_GEN -> CKM_RC5_KEY_GEN
    | _ when is _CKM_RC5_ECB -> CKM_RC5_ECB
    | _ when is _CKM_RC5_CBC -> CKM_RC5_CBC
    | _ when is _CKM_RC5_MAC -> CKM_RC5_MAC
    | _ when is _CKM_RC5_MAC_GENERAL -> CKM_RC5_MAC_GENERAL
    | _ when is _CKM_RC5_CBC_PAD -> CKM_RC5_CBC_PAD
    | _ when is _CKM_IDEA_KEY_GEN -> CKM_IDEA_KEY_GEN
    | _ when is _CKM_IDEA_ECB -> CKM_IDEA_ECB
    | _ when is _CKM_IDEA_CBC -> CKM_IDEA_CBC
    | _ when is _CKM_IDEA_MAC -> CKM_IDEA_MAC
    | _ when is _CKM_IDEA_MAC_GENERAL -> CKM_IDEA_MAC_GENERAL
    | _ when is _CKM_IDEA_CBC_PAD -> CKM_IDEA_CBC_PAD
    | _ when is _CKM_GENERIC_SECRET_KEY_GEN -> CKM_GENERIC_SECRET_KEY_GEN
    | _ when is _CKM_CONCATENATE_BASE_AND_KEY -> CKM_CONCATENATE_BASE_AND_KEY
    | _ when is _CKM_CONCATENATE_BASE_AND_DATA -> CKM_CONCATENATE_BASE_AND_DATA
    | _ when is _CKM_CONCATENATE_DATA_AND_BASE -> CKM_CONCATENATE_DATA_AND_BASE
    | _ when is _CKM_XOR_BASE_AND_DATA -> CKM_XOR_BASE_AND_DATA
    | _ when is _CKM_EXTRACT_KEY_FROM_KEY -> CKM_EXTRACT_KEY_FROM_KEY
    | _ when is _CKM_SSL3_PRE_MASTER_KEY_GEN -> CKM_SSL3_PRE_MASTER_KEY_GEN
    | _ when is _CKM_SSL3_MASTER_KEY_DERIVE -> CKM_SSL3_MASTER_KEY_DERIVE
    | _ when is _CKM_SSL3_KEY_AND_MAC_DERIVE -> CKM_SSL3_KEY_AND_MAC_DERIVE
    | _ when is _CKM_SSL3_MASTER_KEY_DERIVE_DH -> CKM_SSL3_MASTER_KEY_DERIVE_DH
    | _ when is _CKM_TLS_PRE_MASTER_KEY_GEN -> CKM_TLS_PRE_MASTER_KEY_GEN
    | _ when is _CKM_TLS_MASTER_KEY_DERIVE -> CKM_TLS_MASTER_KEY_DERIVE
    | _ when is _CKM_TLS_KEY_AND_MAC_DERIVE -> CKM_TLS_KEY_AND_MAC_DERIVE
    | _ when is _CKM_TLS_MASTER_KEY_DERIVE_DH -> CKM_TLS_MASTER_KEY_DERIVE_DH
    | _ when is _CKM_TLS_PRF -> CKM_TLS_PRF
    | _ when is _CKM_SSL3_MD5_MAC -> CKM_SSL3_MD5_MAC
    | _ when is _CKM_SSL3_SHA1_MAC -> CKM_SSL3_SHA1_MAC
    | _ when is _CKM_MD5_KEY_DERIVATION -> CKM_MD5_KEY_DERIVATION
    | _ when is _CKM_MD2_KEY_DERIVATION -> CKM_MD2_KEY_DERIVATION
    | _ when is _CKM_SHA1_KEY_DERIVATION -> CKM_SHA1_KEY_DERIVATION
    | _ when is _CKM_SHA256_KEY_DERIVATION -> CKM_SHA256_KEY_DERIVATION
    | _ when is _CKM_SHA384_KEY_DERIVATION -> CKM_SHA384_KEY_DERIVATION
    | _ when is _CKM_SHA512_KEY_DERIVATION -> CKM_SHA512_KEY_DERIVATION
    | _ when is _CKM_SHA224_KEY_DERIVATION -> CKM_SHA224_KEY_DERIVATION
    | _ when is _CKM_PBE_MD2_DES_CBC -> CKM_PBE_MD2_DES_CBC
    | _ when is _CKM_PBE_MD5_DES_CBC -> CKM_PBE_MD5_DES_CBC
    | _ when is _CKM_PBE_MD5_CAST_CBC -> CKM_PBE_MD5_CAST_CBC
    | _ when is _CKM_PBE_MD5_CAST3_CBC -> CKM_PBE_MD5_CAST3_CBC
    | _ when is _CKM_PBE_MD5_CAST128_CBC -> CKM_PBE_MD5_CAST128_CBC
    | _ when is _CKM_PBE_SHA1_CAST128_CBC -> CKM_PBE_SHA1_CAST128_CBC
    | _ when is _CKM_PBE_SHA1_RC4_128 -> CKM_PBE_SHA1_RC4_128
    | _ when is _CKM_PBE_SHA1_RC4_40 -> CKM_PBE_SHA1_RC4_40
    | _ when is _CKM_PBE_SHA1_DES3_EDE_CBC -> CKM_PBE_SHA1_DES3_EDE_CBC
    | _ when is _CKM_PBE_SHA1_DES2_EDE_CBC -> CKM_PBE_SHA1_DES2_EDE_CBC
    | _ when is _CKM_PBE_SHA1_RC2_128_CBC -> CKM_PBE_SHA1_RC2_128_CBC
    | _ when is _CKM_PBE_SHA1_RC2_40_CBC -> CKM_PBE_SHA1_RC2_40_CBC
    | _ when is _CKM_PKCS5_PBKD2 -> CKM_PKCS5_PBKD2
    | _ when is _CKM_PBA_SHA1_WITH_SHA1_HMAC -> CKM_PBA_SHA1_WITH_SHA1_HMAC
    | _ when is _CKM_WTLS_PRE_MASTER_KEY_GEN -> CKM_WTLS_PRE_MASTER_KEY_GEN
    | _ when is _CKM_WTLS_MASTER_KEY_DERIVE -> CKM_WTLS_MASTER_KEY_DERIVE
    | _ when is _CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC -> CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
    | _ when is _CKM_WTLS_PRF -> CKM_WTLS_PRF
    | _ when is _CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE -> CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
    | _ when is _CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE -> CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
    | _ when is _CKM_KEY_WRAP_LYNKS -> CKM_KEY_WRAP_LYNKS
    | _ when is _CKM_KEY_WRAP_SET_OAEP -> CKM_KEY_WRAP_SET_OAEP
    | _ when is _CKM_CMS_SIG -> CKM_CMS_SIG
    | _ when is _CKM_KIP_DERIVE -> CKM_KIP_DERIVE
    | _ when is _CKM_KIP_WRAP -> CKM_KIP_WRAP
    | _ when is _CKM_KIP_MAC -> CKM_KIP_MAC
    | _ when is _CKM_CAMELLIA_KEY_GEN -> CKM_CAMELLIA_KEY_GEN
    | _ when is _CKM_CAMELLIA_ECB -> CKM_CAMELLIA_ECB
    | _ when is _CKM_CAMELLIA_CBC -> CKM_CAMELLIA_CBC
    | _ when is _CKM_CAMELLIA_MAC -> CKM_CAMELLIA_MAC
    | _ when is _CKM_CAMELLIA_MAC_GENERAL -> CKM_CAMELLIA_MAC_GENERAL
    | _ when is _CKM_CAMELLIA_CBC_PAD -> CKM_CAMELLIA_CBC_PAD
    | _ when is _CKM_CAMELLIA_ECB_ENCRYPT_DATA -> CKM_CAMELLIA_ECB_ENCRYPT_DATA
    | _ when is _CKM_CAMELLIA_CBC_ENCRYPT_DATA -> CKM_CAMELLIA_CBC_ENCRYPT_DATA
    | _ when is _CKM_CAMELLIA_CTR -> CKM_CAMELLIA_CTR
    | _ when is _CKM_ARIA_KEY_GEN -> CKM_ARIA_KEY_GEN
    | _ when is _CKM_ARIA_ECB -> CKM_ARIA_ECB
    | _ when is _CKM_ARIA_CBC -> CKM_ARIA_CBC
    | _ when is _CKM_ARIA_MAC -> CKM_ARIA_MAC
    | _ when is _CKM_ARIA_MAC_GENERAL -> CKM_ARIA_MAC_GENERAL
    | _ when is _CKM_ARIA_CBC_PAD -> CKM_ARIA_CBC_PAD
    | _ when is _CKM_ARIA_ECB_ENCRYPT_DATA -> CKM_ARIA_ECB_ENCRYPT_DATA
    | _ when is _CKM_ARIA_CBC_ENCRYPT_DATA -> CKM_ARIA_CBC_ENCRYPT_DATA
    | _ when is _CKM_SKIPJACK_KEY_GEN -> CKM_SKIPJACK_KEY_GEN
    | _ when is _CKM_SKIPJACK_ECB64 -> CKM_SKIPJACK_ECB64
    | _ when is _CKM_SKIPJACK_CBC64 -> CKM_SKIPJACK_CBC64
    | _ when is _CKM_SKIPJACK_OFB64 -> CKM_SKIPJACK_OFB64
    | _ when is _CKM_SKIPJACK_CFB64 -> CKM_SKIPJACK_CFB64
    | _ when is _CKM_SKIPJACK_CFB32 -> CKM_SKIPJACK_CFB32
    | _ when is _CKM_SKIPJACK_CFB16 -> CKM_SKIPJACK_CFB16
    | _ when is _CKM_SKIPJACK_CFB8 -> CKM_SKIPJACK_CFB8
    | _ when is _CKM_SKIPJACK_WRAP -> CKM_SKIPJACK_WRAP
    | _ when is _CKM_SKIPJACK_PRIVATE_WRAP -> CKM_SKIPJACK_PRIVATE_WRAP
    | _ when is _CKM_SKIPJACK_RELAYX -> CKM_SKIPJACK_RELAYX
    | _ when is _CKM_KEA_KEY_PAIR_GEN -> CKM_KEA_KEY_PAIR_GEN
    | _ when is _CKM_KEA_KEY_DERIVE -> CKM_KEA_KEY_DERIVE
    | _ when is _CKM_FORTEZZA_TIMESTAMP -> CKM_FORTEZZA_TIMESTAMP
    | _ when is _CKM_BATON_KEY_GEN -> CKM_BATON_KEY_GEN
    | _ when is _CKM_BATON_ECB128 -> CKM_BATON_ECB128
    | _ when is _CKM_BATON_ECB96 -> CKM_BATON_ECB96
    | _ when is _CKM_BATON_CBC128 -> CKM_BATON_CBC128
    | _ when is _CKM_BATON_COUNTER -> CKM_BATON_COUNTER
    | _ when is _CKM_BATON_SHUFFLE -> CKM_BATON_SHUFFLE
    | _ when is _CKM_BATON_WRAP -> CKM_BATON_WRAP
    | _ when is _CKM_EC_KEY_PAIR_GEN -> CKM_EC_KEY_PAIR_GEN
    | _ when is _CKM_ECDSA -> CKM_ECDSA
    | _ when is _CKM_ECDSA_SHA1 -> CKM_ECDSA_SHA1
    | _ when is _CKM_ECDH1_DERIVE -> CKM_ECDH1_DERIVE
    | _ when is _CKM_ECDH1_COFACTOR_DERIVE -> CKM_ECDH1_COFACTOR_DERIVE
    | _ when is _CKM_ECMQV_DERIVE -> CKM_ECMQV_DERIVE
    | _ when is _CKM_JUNIPER_KEY_GEN -> CKM_JUNIPER_KEY_GEN
    | _ when is _CKM_JUNIPER_ECB128 -> CKM_JUNIPER_ECB128
    | _ when is _CKM_JUNIPER_CBC128 -> CKM_JUNIPER_CBC128
    | _ when is _CKM_JUNIPER_COUNTER -> CKM_JUNIPER_COUNTER
    | _ when is _CKM_JUNIPER_SHUFFLE -> CKM_JUNIPER_SHUFFLE
    | _ when is _CKM_JUNIPER_WRAP -> CKM_JUNIPER_WRAP
    | _ when is _CKM_FASTHASH -> CKM_FASTHASH
    | _ when is _CKM_AES_KEY_GEN -> CKM_AES_KEY_GEN
    | _ when is _CKM_AES_ECB -> CKM_AES_ECB
    | _ when is _CKM_AES_CBC -> CKM_AES_CBC
    | _ when is _CKM_AES_MAC -> CKM_AES_MAC
    | _ when is _CKM_AES_MAC_GENERAL -> CKM_AES_MAC_GENERAL
    | _ when is _CKM_AES_CBC_PAD -> CKM_AES_CBC_PAD
    | _ when is _CKM_AES_CTR -> CKM_AES_CTR
    | _ when is _CKM_BLOWFISH_KEY_GEN -> CKM_BLOWFISH_KEY_GEN
    | _ when is _CKM_BLOWFISH_CBC -> CKM_BLOWFISH_CBC
    | _ when is _CKM_TWOFISH_KEY_GEN -> CKM_TWOFISH_KEY_GEN
    | _ when is _CKM_TWOFISH_CBC -> CKM_TWOFISH_CBC
    | _ when is _CKM_DES_ECB_ENCRYPT_DATA -> CKM_DES_ECB_ENCRYPT_DATA
    | _ when is _CKM_DES_CBC_ENCRYPT_DATA -> CKM_DES_CBC_ENCRYPT_DATA
    | _ when is _CKM_DES3_ECB_ENCRYPT_DATA -> CKM_DES3_ECB_ENCRYPT_DATA
    | _ when is _CKM_DES3_CBC_ENCRYPT_DATA -> CKM_DES3_CBC_ENCRYPT_DATA
    | _ when is _CKM_AES_ECB_ENCRYPT_DATA -> CKM_AES_ECB_ENCRYPT_DATA
    | _ when is _CKM_AES_CBC_ENCRYPT_DATA -> CKM_AES_CBC_ENCRYPT_DATA
    | _ when is _CKM_DSA_PARAMETER_GEN -> CKM_DSA_PARAMETER_GEN
    | _ when is _CKM_DH_PKCS_PARAMETER_GEN -> CKM_DH_PKCS_PARAMETER_GEN
    | _ when is _CKM_X9_42_DH_PARAMETER_GEN -> CKM_X9_42_DH_PARAMETER_GEN
    | _ when is _CKM_VENDOR_DEFINED -> CKM_VENDOR_DEFINED
    | _ when is _CKM_GOSTR3410_KEY_PAIR_GEN -> CKM_GOSTR3410_KEY_PAIR_GEN
    | _ when is _CKM_GOSTR3410 -> CKM_GOSTR3410
    | _ when is _CKM_GOSTR3410_WITH_GOSTR3411 -> CKM_GOSTR3410_WITH_GOSTR3411
    | _ when is _CKM_GOSTR3411 -> CKM_GOSTR3411
    | _ when is _CKM_GOSTR3411_HMAC -> CKM_GOSTR3411_HMAC
    | _ when is _CKM_AES_KEY_WRAP -> CKM_AES_KEY_WRAP
    | _ -> CKM_CS_UNKNOWN t
