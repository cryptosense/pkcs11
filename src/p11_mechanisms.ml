(** The type of kinds that applies to a given mechanism. There are two
    flavor of kinds: kinds that come from the standard (in particular
    table 34 of v2.20); and tags that we apply to groups of mechanisms.  *)
type kind =
  (* kinds from the standard *)
  | Encrypt                     (* Encrypt & Decrypt *)
  | Sign                        (* Sign & Verify *)
  | SignRecover                 (* Sign Recover & Verify recover *)
  | Wrap                        (* Wrap & Unwrap *)
  | Derive
  | Digest
  | Generate                    (* GenerateKey or GenerateKeypair *)


  | Symmetric
  | Asymmetric

  | DES
  | DES3
  | AES
  | RSA
  | DH
  | EC
  (* todo: V2_20, V2_30, V2_40?  *)


(* There are three ways to structure this function: following the
   numbering of mechanisms in the pkcs11 header, following the
   structure of table 34, or grouping the mechanism that are similar
   together.  Since all the solutions have drawbacks, we chose here to
   follow the numbering of values in the header, to make it easier to
   add new values. *)
let kinds : Pkcs11.CK_MECHANISM_TYPE.u -> kind list =
  let open Pkcs11.CK_MECHANISM_TYPE in
  function
    | CKM_RSA_PKCS_KEY_PAIR_GEN -> [Generate; Asymmetric; RSA]
    | CKM_RSA_PKCS -> [Encrypt; Sign; SignRecover; Wrap; RSA; Asymmetric]
    | CKM_RSA_9796 -> [Sign; SignRecover; RSA; Asymmetric]
    | CKM_RSA_X_509 -> [Encrypt; Sign; SignRecover; Wrap; RSA; Asymmetric]
    | CKM_MD2_RSA_PKCS -> [Sign; Asymmetric; RSA]
    | CKM_MD5_RSA_PKCS -> [Sign; Asymmetric; RSA]
    | CKM_SHA1_RSA_PKCS -> [Sign; Asymmetric; RSA]
    | CKM_RIPEMD128_RSA_PKCS -> [Sign; Asymmetric; RSA]
    | CKM_RIPEMD160_RSA_PKCS -> [Sign; Asymmetric; RSA]
    | CKM_RSA_PKCS_OAEP -> [Encrypt; Wrap; Asymmetric; RSA]
    | CKM_RSA_X9_31_KEY_PAIR_GEN -> [Generate; Asymmetric; RSA]
    | CKM_RSA_X9_31 -> [Sign; Asymmetric; RSA]
    | CKM_SHA1_RSA_X9_31 -> [Sign; Asymmetric; RSA]
    | CKM_RSA_PKCS_PSS -> [Sign; Asymmetric; RSA]
    | CKM_SHA1_RSA_PKCS_PSS -> [Sign; Asymmetric; RSA]
    | CKM_DSA_KEY_PAIR_GEN -> [Generate; Asymmetric]
    | CKM_DSA -> [Sign; Asymmetric]
    | CKM_DSA_SHA1 -> [Sign; Asymmetric]
    | CKM_DH_PKCS_KEY_PAIR_GEN -> [Generate; Asymmetric]
    | CKM_DH_PKCS_DERIVE -> [Derive]

    | CKM_X9_42_DH_KEY_PAIR_GEN -> [Generate; Asymmetric]
    | CKM_X9_42_DH_DERIVE -> [Derive; Asymmetric]
    | CKM_X9_42_DH_HYBRID_DERIVE -> [Derive; Asymmetric]
    | CKM_X9_42_MQV_DERIVE -> [Derive; Asymmetric]

    | CKM_SHA256_RSA_PKCS
    | CKM_SHA384_RSA_PKCS
    | CKM_SHA512_RSA_PKCS
    | CKM_SHA256_RSA_PKCS_PSS
    | CKM_SHA384_RSA_PKCS_PSS
    | CKM_SHA512_RSA_PKCS_PSS
    | CKM_SHA224_RSA_PKCS
    | CKM_SHA224_RSA_PKCS_PSS -> [Sign; Asymmetric; RSA]

    | CKM_RC2_KEY_GEN -> [Generate; Symmetric]
    | CKM_RC2_ECB -> [Encrypt; Wrap; Symmetric]
    | CKM_RC2_CBC -> [Encrypt; Wrap; Symmetric]
    | CKM_RC2_MAC -> [Sign; Symmetric]
    | CKM_RC2_MAC_GENERAL -> [Sign; Symmetric]
    | CKM_RC2_CBC_PAD -> [Encrypt; Wrap; Symmetric]

    | CKM_RC4_KEY_GEN -> [Generate; Symmetric]
    | CKM_RC4 -> [Encrypt; Symmetric]

    | CKM_DES_KEY_GEN -> [Generate; Symmetric; DES]
    | CKM_DES_ECB -> [Encrypt; Wrap; Symmetric; DES]
    | CKM_DES_CBC -> [Encrypt; Wrap; Symmetric; DES]
    | CKM_DES_MAC -> [Sign; Symmetric; DES]
    | CKM_DES_MAC_GENERAL -> [Sign; Symmetric; DES]
    | CKM_DES_CBC_PAD  -> [Encrypt; Wrap; Symmetric; DES]
    | CKM_DES2_KEY_GEN
    | CKM_DES3_KEY_GEN -> [Generate; Symmetric; DES3]
    | CKM_DES3_ECB
    | CKM_DES3_CBC  -> [Encrypt; Wrap; Symmetric; DES3]
    | CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL -> [Sign; Symmetric; DES3]
    | CKM_DES3_CBC_PAD -> [Encrypt; Wrap; Symmetric; DES3]

    | CKM_CDMF_KEY_GEN ->  [Generate; Symmetric]
    | CKM_CDMF_ECB
    | CKM_CDMF_CBC -> [Encrypt; Wrap; Symmetric]
    | CKM_CDMF_MAC
    | CKM_CDMF_MAC_GENERAL ->  [Sign; Symmetric]
    | CKM_CDMF_CBC_PAD -> [Encrypt; Wrap; Symmetric]
    | CKM_DES_OFB64
    | CKM_DES_OFB8
    | CKM_DES_CFB64
    | CKM_DES_CFB8  -> []       (* The reference manual does not say anything *)
    | CKM_MD2 -> [Digest]
    | CKM_MD2_HMAC -> [Sign]
    | CKM_MD2_HMAC_GENERAL -> [Sign]
    | CKM_MD5 -> [Digest]
    | CKM_MD5_HMAC -> [Sign]
    | CKM_MD5_HMAC_GENERAL -> [Sign]
    | CKM_SHA_1 -> [Digest]
    | CKM_SHA_1_HMAC  -> [Sign]
    | CKM_SHA_1_HMAC_GENERAL -> [Sign]
    | CKM_RIPEMD128 -> [Digest]
    | CKM_RIPEMD128_HMAC -> [Sign]
    | CKM_RIPEMD128_HMAC_GENERAL -> [Sign]
    | CKM_RIPEMD160 -> [Digest]
    | CKM_RIPEMD160_HMAC -> [Sign]
    | CKM_RIPEMD160_HMAC_GENERAL -> [Sign]
    | CKM_SHA256 -> [Digest]
    | CKM_SHA256_HMAC -> [Sign]
    | CKM_SHA256_HMAC_GENERAL -> [Sign]
    | CKM_SHA224 -> [Digest]
    | CKM_SHA224_HMAC -> [Sign]
    | CKM_SHA224_HMAC_GENERAL -> [Sign]
    | CKM_SHA384 -> [Digest]
    | CKM_SHA384_HMAC  -> [Sign]
    | CKM_SHA384_HMAC_GENERAL -> [Sign]
    | CKM_SHA512 -> [Digest]
    | CKM_SHA512_HMAC -> [Sign]
    | CKM_SHA512_HMAC_GENERAL -> [Sign]

    (* Not in thse standard *)
    | CKM_SECURID_KEY_GEN
    | CKM_SECURID
    | CKM_HOTP_KEY_GEN
    | CKM_HOTP
    | CKM_ACTI
    | CKM_ACTI_KEY_GEN -> []

    | CKM_CAST_KEY_GEN -> [Generate; Symmetric]
    | CKM_CAST_ECB -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST_CBC -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST_MAC -> [Symmetric; Sign]
    | CKM_CAST_MAC_GENERAL -> [Symmetric; Sign]
    | CKM_CAST_CBC_PAD -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST3_KEY_GEN -> [Generate; Symmetric]
    | CKM_CAST3_ECB -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST3_CBC -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST3_MAC -> [Symmetric; Sign]
    | CKM_CAST3_MAC_GENERAL -> [Symmetric; Sign]
    | CKM_CAST3_CBC_PAD -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST128_KEY_GEN -> [Generate; Symmetric]
    | CKM_CAST128_ECB -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST128_CBC -> [Symmetric; Encrypt; Wrap]
    | CKM_CAST128_MAC -> [Symmetric; Sign]
    | CKM_CAST128_MAC_GENERAL -> [Symmetric; Sign]
    | CKM_CAST128_CBC_PAD -> [Symmetric; Encrypt; Wrap]

    | CKM_RC5_KEY_GEN -> [Generate; Symmetric]
    | CKM_RC5_ECB -> [Symmetric; Encrypt; Wrap]
    | CKM_RC5_CBC -> [Symmetric; Encrypt; Wrap]
    | CKM_RC5_MAC -> [Symmetric; Sign]
    | CKM_RC5_MAC_GENERAL -> [Symmetric; Sign]
    | CKM_RC5_CBC_PAD -> [Symmetric; Encrypt; Wrap]

    | CKM_IDEA_KEY_GEN -> [Generate; Symmetric]
    | CKM_IDEA_ECB  -> [Symmetric; Encrypt; Wrap ]
    | CKM_IDEA_CBC  -> [Symmetric; Encrypt; Wrap ]
    | CKM_IDEA_MAC-> [Symmetric; Sign]
    | CKM_IDEA_MAC_GENERAL -> [Symmetric; Sign]
    | CKM_IDEA_CBC_PAD -> [Symmetric; Encrypt; Wrap]

    | CKM_GENERIC_SECRET_KEY_GEN -> [Generate]
    | CKM_CONCATENATE_BASE_AND_KEY -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
    | CKM_CONCATENATE_BASE_AND_DATA -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
    | CKM_CONCATENATE_DATA_AND_BASE -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
    | CKM_XOR_BASE_AND_DATA -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
    | CKM_EXTRACT_KEY_FROM_KEY -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)

    | CKM_SSL3_PRE_MASTER_KEY_GEN -> [Generate; Symmetric]
    | CKM_SSL3_MASTER_KEY_DERIVE -> [Derive]
    | CKM_SSL3_KEY_AND_MAC_DERIVE -> [Derive]
    | CKM_SSL3_MASTER_KEY_DERIVE_DH -> [Derive]
    | CKM_TLS_PRE_MASTER_KEY_GEN -> [Generate]
    | CKM_TLS_MASTER_KEY_DERIVE -> [Derive]
    | CKM_TLS_KEY_AND_MAC_DERIVE -> [Derive]
    | CKM_TLS_MASTER_KEY_DERIVE_DH -> [Derive]
    | CKM_TLS_PRF -> [Derive]
    | CKM_SSL3_MD5_MAC -> [Sign]
    | CKM_SSL3_SHA1_MAC -> [Sign]

    | CKM_MD5_KEY_DERIVATION -> [Derive]
    | CKM_MD2_KEY_DERIVATION -> [Derive]
    | CKM_SHA1_KEY_DERIVATION -> [Derive]
    | CKM_SHA256_KEY_DERIVATION -> [Derive]
    | CKM_SHA384_KEY_DERIVATION -> [Derive]
    | CKM_SHA512_KEY_DERIVATION -> [Derive]
    | CKM_SHA224_KEY_DERIVATION -> [Derive]

    | CKM_PBE_MD2_DES_CBC -> [Generate; Symmetric]
    | CKM_PBE_MD5_DES_CBC -> [Generate; Symmetric]
    | CKM_PBE_MD5_CAST_CBC -> [Generate; Symmetric]
    | CKM_PBE_MD5_CAST3_CBC -> [Generate; Symmetric]
    | CKM_PBE_MD5_CAST128_CBC -> [Generate; Symmetric]
    | CKM_PBE_SHA1_CAST128_CBC -> [Generate; Symmetric]
    | CKM_PBE_SHA1_RC4_128 ->  [Generate; Symmetric]
    | CKM_PBE_SHA1_RC4_40 ->  [Generate; Symmetric]
    | CKM_PBE_SHA1_DES3_EDE_CBC -> [Generate; Symmetric]
    | CKM_PBE_SHA1_DES2_EDE_CBC -> [Generate; Symmetric]
    | CKM_PBE_SHA1_RC2_128_CBC -> [Generate; Symmetric]
    | CKM_PBE_SHA1_RC2_40_CBC -> [Generate; Symmetric]
    | CKM_PKCS5_PBKD2 -> [Generate; Symmetric]
    | CKM_PBA_SHA1_WITH_SHA1_HMAC -> [Generate; Symmetric]

    | CKM_WTLS_PRE_MASTER_KEY_GEN -> [Generate; Symmetric]
    | CKM_WTLS_MASTER_KEY_DERIVE -> [Derive]
    | CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC -> [Derive]
    | CKM_WTLS_PRF -> [Derive]
    | CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE -> [Derive]
    | CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE -> [Derive]

    | CKM_KEY_WRAP_LYNKS
    | CKM_KEY_WRAP_SET_OAEP  -> [Wrap]
    | CKM_CMS_SIG -> [Sign; SignRecover]

    (* not in the standard *)
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
    | CKM_ARIA_CBC_ENCRYPT_DATA -> []

    | CKM_SKIPJACK_KEY_GEN -> [Generate; Symmetric]
    | CKM_SKIPJACK_ECB64
    | CKM_SKIPJACK_CBC64
    | CKM_SKIPJACK_OFB64
    | CKM_SKIPJACK_CFB64
    | CKM_SKIPJACK_CFB32
    | CKM_SKIPJACK_CFB16
    | CKM_SKIPJACK_CFB8 -> [Encrypt]
    | CKM_SKIPJACK_WRAP -> [Wrap]

    | CKM_SKIPJACK_PRIVATE_WRAP -> [Wrap]
    | CKM_SKIPJACK_RELAYX -> [Wrap]

    | CKM_KEA_KEY_PAIR_GEN -> [Generate]
    | CKM_KEA_KEY_DERIVE -> [Derive]
    | CKM_FORTEZZA_TIMESTAMP -> [Sign]
    | CKM_BATON_KEY_GEN -> [Generate]

    | CKM_BATON_ECB128
    | CKM_BATON_ECB96
    | CKM_BATON_CBC128
    | CKM_BATON_COUNTER
    | CKM_BATON_SHUFFLE -> [Encrypt]
    | CKM_BATON_WRAP -> [Wrap]

    | CKM_EC_KEY_PAIR_GEN -> [EC; Asymmetric; Generate]
    | CKM_ECDSA -> [EC; Asymmetric; Sign]
    | CKM_ECDSA_SHA1 -> [EC; Asymmetric; Sign]
    | CKM_ECDH1_DERIVE -> [EC; Asymmetric; Derive; DH]
    | CKM_ECDH1_COFACTOR_DERIVE -> [EC; Asymmetric; Derive; DH]
    | CKM_ECMQV_DERIVE -> [EC; Asymmetric; Derive; DH]

    | CKM_JUNIPER_KEY_GEN -> [Generate; Symmetric]
    | CKM_JUNIPER_ECB128 -> [Encrypt]
    | CKM_JUNIPER_CBC128 -> [Encrypt]
    | CKM_JUNIPER_COUNTER -> [Encrypt]
    | CKM_JUNIPER_SHUFFLE -> [Encrypt]
    | CKM_JUNIPER_WRAP -> [Wrap]
    | CKM_FASTHASH -> [Digest]

    | CKM_AES_KEY_GEN
      -> [AES; Generate; Symmetric]

    | CKM_AES_ECB
    | CKM_AES_CBC
      -> [ AES; Symmetric; Encrypt; Wrap ]

    | CKM_AES_MAC
    | CKM_AES_MAC_GENERAL
      -> [ AES; Symmetric; Sign ]

    | CKM_AES_CBC_PAD
      -> [ AES; Symmetric; Encrypt; Wrap ]

    | CKM_AES_CTR
      -> [ AES; Symmetric; Encrypt; Wrap ]

    | CKM_BLOWFISH_KEY_GEN
    | CKM_BLOWFISH_CBC
    | CKM_TWOFISH_KEY_GEN
    | CKM_TWOFISH_CBC -> []

    | CKM_DES_ECB_ENCRYPT_DATA
    | CKM_DES_CBC_ENCRYPT_DATA -> [DES; Symmetric; Derive]
    | CKM_DES3_ECB_ENCRYPT_DATA
    | CKM_DES3_CBC_ENCRYPT_DATA -> [DES3; Symmetric; Derive]
    | CKM_AES_ECB_ENCRYPT_DATA
    | CKM_AES_CBC_ENCRYPT_DATA -> [AES; Symmetric; Derive]
    | CKM_DSA_PARAMETER_GEN
    | CKM_DH_PKCS_PARAMETER_GEN
    | CKM_X9_42_DH_PARAMETER_GEN -> [Generate]
    | CKM_VENDOR_DEFINED
    | CKM_CS_UNKNOWN _ -> []

(* Return whether [m] has all kinds [k]. *)
let is (k: kind list) (m: Pkcs11.CK_MECHANISM_TYPE.u) =
  let kinds = kinds m in
    List.for_all (fun k -> List.mem k kinds) k

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

    | CKM_PKCS5_PBKD2  -> fail ()
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
    | CKM_CS_UNKNOWN _ -> fail ()
