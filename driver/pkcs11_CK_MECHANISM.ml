open Ctypes
open Ctypes_helpers

type _t

type t = _t structure

let ck_mechanism : t typ = structure "CK_MECHANISM"

let ( -: ) ty label = smart_field ck_mechanism label ty

let mechanism = Pkcs11_CK_MECHANISM_TYPE.typ -: "mechanism"

let parameter = Reachable_ptr.typ void -: "pParameter"

let parameter_len = ulong -: "pParameterLen"

let () = seal ck_mechanism

type argument =
  | No_argument
  | OAEP of P11_rsa_pkcs_oaep_params.t
  | PSS of P11_rsa_pkcs_pss_params.t
  | String of string
  | Ulong of P11_ulong.t
  | Derivation_string of P11_hex_data.t
  | AES_CBC_encrypt of P11_aes_cbc_encrypt_data_params.t
  | DES_CBC_encrypt of P11_des_cbc_encrypt_data_params.t
  | ECDH1 of P11_ecdh1_derive_params.t
  | ECMQV of P11_ecmqv_derive_params.t
  | PBKD2 of P11_pkcs5_pbkd2_data_params.t
  | AES_CTR of P11_aes_ctr_params.t
  | GCM of P11_gcm_params.t

let aes_key_wrap_argument p =
  match P11_aes_key_wrap_params.explicit_iv p with
  | None -> No_argument
  | Some iv -> String iv

let argument =
  let open P11_mechanism in
  function
  | CKM_SHA_1 -> No_argument
  | CKM_SHA224 -> No_argument
  | CKM_SHA256 -> No_argument
  | CKM_SHA384 -> No_argument
  | CKM_SHA512 -> No_argument
  | CKM_MD5 -> No_argument
  | CKM_RSA_PKCS_KEY_PAIR_GEN -> No_argument
  | CKM_RSA_X9_31_KEY_PAIR_GEN -> No_argument
  | CKM_RSA_PKCS -> No_argument
  | CKM_RSA_PKCS_OAEP p -> OAEP p
  | CKM_RSA_X_509 -> No_argument
  | CKM_RSA_PKCS_PSS p -> PSS p
  | CKM_SHA1_RSA_PKCS -> No_argument
  | CKM_SHA224_RSA_PKCS -> No_argument
  | CKM_SHA256_RSA_PKCS -> No_argument
  | CKM_SHA384_RSA_PKCS -> No_argument
  | CKM_SHA512_RSA_PKCS -> No_argument
  | CKM_SHA1_RSA_PKCS_PSS p -> PSS p
  | CKM_SHA224_RSA_PKCS_PSS p -> PSS p
  | CKM_SHA256_RSA_PKCS_PSS p -> PSS p
  | CKM_SHA384_RSA_PKCS_PSS p -> PSS p
  | CKM_SHA512_RSA_PKCS_PSS p -> PSS p
  | CKM_AES_KEY_GEN -> No_argument
  | CKM_AES_ECB -> No_argument
  | CKM_AES_CBC p -> String p
  | CKM_AES_CBC_PAD p -> String p
  | CKM_AES_MAC -> No_argument
  | CKM_AES_MAC_GENERAL p -> Ulong p
  | CKM_AES_ECB_ENCRYPT_DATA p -> Derivation_string p
  | CKM_AES_CBC_ENCRYPT_DATA p -> AES_CBC_encrypt p
  | CKM_DES_KEY_GEN -> No_argument
  | CKM_DES_ECB -> No_argument
  | CKM_DES_CBC p -> String p
  | CKM_DES_CBC_PAD p -> String p
  | CKM_DES_MAC -> No_argument
  | CKM_DES_MAC_GENERAL p -> Ulong p
  | CKM_DES_ECB_ENCRYPT_DATA p -> Derivation_string p
  | CKM_DES_CBC_ENCRYPT_DATA p -> DES_CBC_encrypt p
  | CKM_DES3_KEY_GEN -> No_argument
  | CKM_DES3_ECB -> No_argument
  | CKM_DES3_CBC p -> String p
  | CKM_DES3_CBC_PAD p -> String p
  | CKM_DES3_MAC -> No_argument
  | CKM_DES3_MAC_GENERAL p -> Ulong p
  | CKM_DES3_ECB_ENCRYPT_DATA p -> Derivation_string p
  | CKM_DES3_CBC_ENCRYPT_DATA p -> DES_CBC_encrypt p
  | CKM_CONCATENATE_BASE_AND_DATA p -> Derivation_string p
  | CKM_CONCATENATE_DATA_AND_BASE p -> Derivation_string p
  | CKM_XOR_BASE_AND_DATA p -> Derivation_string p
  | CKM_EXTRACT_KEY_FROM_KEY p -> Ulong p
  | CKM_CONCATENATE_BASE_AND_KEY p -> Ulong p
  | CKM_EC_KEY_PAIR_GEN -> No_argument
  | CKM_ECDSA -> No_argument
  | CKM_ECDSA_SHA1 -> No_argument
  | CKM_ECDSA_SHA224 -> No_argument
  | CKM_ECDSA_SHA256 -> No_argument
  | CKM_ECDSA_SHA384 -> No_argument
  | CKM_ECDSA_SHA512 -> No_argument
  | CKM_ECDH1_DERIVE p -> ECDH1 p
  | CKM_ECDH1_COFACTOR_DERIVE p -> ECDH1 p
  | CKM_ECMQV_DERIVE p -> ECMQV p
  | CKM_PKCS5_PBKD2 p -> PBKD2 p
  | CKM_DSA_KEY_PAIR_GEN -> No_argument
  | CKM_DSA_SHA1 -> No_argument
  | CKM_DSA_SHA224 -> No_argument
  | CKM_DSA_SHA256 -> No_argument
  | CKM_DSA_SHA384 -> No_argument
  | CKM_DSA_SHA512 -> No_argument
  | CKM_AES_CTR p -> AES_CTR p
  | CKM_AES_GCM p -> GCM p
  | CKM_SHA_1_HMAC -> No_argument
  | CKM_SHA224_HMAC -> No_argument
  | CKM_SHA256_HMAC -> No_argument
  | CKM_SHA384_HMAC -> No_argument
  | CKM_SHA512_HMAC -> No_argument
  | CKM_GENERIC_SECRET_KEY_GEN -> No_argument
  | CKM_AES_KEY_WRAP p -> aes_key_wrap_argument p
  | CKM_CS_UNKNOWN _ -> No_argument

let argument_params argument =
  let struct_ params ctype make_ctype =
    let params = make_ctype params in
    let param = to_voidp (addr params) in
    let param_len = Unsigned.ULong.of_int (sizeof ctype) in
    (param, param_len)
  in
  match argument with
  | No_argument -> (null, Unsigned.ULong.zero)
  | OAEP p ->
    struct_ p Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.t
      Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.make
  | PSS p ->
    struct_ p Pkcs11_CK_RSA_PKCS_PSS_PARAMS.t Pkcs11_CK_RSA_PKCS_PSS_PARAMS.make
  | String p ->
    let params = Pkcs11_data.of_string p in
    let char_ptr = Pkcs11_data.get_content params in
    let param_len = Pkcs11_data.get_length params in
    (to_voidp char_ptr, param_len)
  | Ulong p ->
    let ptr = allocate ulong p in
    (to_voidp ptr, Unsigned.ULong.of_int (sizeof ulong))
  | Derivation_string p ->
    struct_ p Pkcs11_CK_KEY_DERIVATION_STRING_DATA.t
      Pkcs11_CK_KEY_DERIVATION_STRING_DATA.make
  | AES_CBC_encrypt p ->
    struct_ p Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.t
      Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.make
  | DES_CBC_encrypt p ->
    struct_ p Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.t
      Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.make
  | ECDH1 p ->
    struct_ p Pkcs11_CK_ECDH1_DERIVE_PARAMS.t Pkcs11_CK_ECDH1_DERIVE_PARAMS.make
  | ECMQV p ->
    struct_ p Pkcs11_CK_ECMQV_DERIVE_PARAMS.t Pkcs11_CK_ECMQV_DERIVE_PARAMS.make
  | PBKD2 p ->
    struct_ p Pkcs11_CK_PKCS5_PBKD2_PARAMS.t Pkcs11_CK_PKCS5_PBKD2_PARAMS.make
  | AES_CTR p ->
    struct_ p Pkcs11_CK_AES_CTR_PARAMS.t Pkcs11_CK_AES_CTR_PARAMS.make
  | GCM p -> struct_ p Pkcs11_CK_GCM_PARAMS.t Pkcs11_CK_GCM_PARAMS.make

let make x =
  let ckm = Pkcs11_CK_MECHANISM_TYPE.make @@ P11_mechanism.mechanism_type x in
  let (param, param_len) = argument_params @@ argument x in
  let m = make ck_mechanism in
  setf m mechanism ckm;
  Reachable_ptr.setf m parameter param;
  setf m parameter_len param_len;
  m

let unsafe_get_string t = view_string t parameter_len parameter

let unsafe_get_struct t typ view =
  let p = from_voidp typ (Reachable_ptr.getf t parameter) in
  view !@p

let unsafe_get_oaep t =
  unsafe_get_struct t Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.t
    Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.view

let unsafe_get_pss t =
  unsafe_get_struct t Pkcs11_CK_RSA_PKCS_PSS_PARAMS.t
    Pkcs11_CK_RSA_PKCS_PSS_PARAMS.view

let unsafe_get_derivation_string t =
  unsafe_get_struct t Pkcs11_CK_KEY_DERIVATION_STRING_DATA.t
    Pkcs11_CK_KEY_DERIVATION_STRING_DATA.view

let unsafe_get_aes_cbc_param t =
  unsafe_get_struct t
    Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.t
    Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.view

let unsafe_get_des_cbc_param t =
  unsafe_get_struct t
    Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.t
    Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.view

let unsafe_get_ecdh1_derive_param t =
  unsafe_get_struct t Pkcs11_CK_ECDH1_DERIVE_PARAMS.t
    Pkcs11_CK_ECDH1_DERIVE_PARAMS.view

let unsafe_get_ecmqv_derive_param t =
  unsafe_get_struct t Pkcs11_CK_ECMQV_DERIVE_PARAMS.t
    Pkcs11_CK_ECMQV_DERIVE_PARAMS.view

let unsafe_get_ulong t =
  let p = Reachable_ptr.getf t parameter |> from_voidp ulong in
  !@p

let unsafe_get_aes_key_wrap_option t =
  let open P11_aes_key_wrap_params in
  match view_string_option t parameter_len parameter with
  | None -> default
  | Some s -> explicit s

let view t =
  let module T = P11_mechanism_type in
  let open P11_mechanism in
  let ul = getf t mechanism in
  match Pkcs11_CK_MECHANISM_TYPE.view ul with
  | T.CKM_SHA_1 -> CKM_SHA_1
  | T.CKM_SHA224 -> CKM_SHA224
  | T.CKM_SHA256 -> CKM_SHA256
  | T.CKM_SHA384 -> CKM_SHA384
  | T.CKM_SHA512 -> CKM_SHA512
  | T.CKM_MD5 -> CKM_MD5
  | T.CKM_RSA_PKCS_KEY_PAIR_GEN -> CKM_RSA_PKCS_KEY_PAIR_GEN
  | T.CKM_RSA_X9_31_KEY_PAIR_GEN -> CKM_RSA_X9_31_KEY_PAIR_GEN
  | T.CKM_RSA_PKCS -> CKM_RSA_PKCS
  | T.CKM_RSA_PKCS_OAEP -> CKM_RSA_PKCS_OAEP (unsafe_get_oaep t)
  | T.CKM_RSA_X_509 -> CKM_RSA_X_509
  | T.CKM_RSA_PKCS_PSS -> CKM_RSA_PKCS_PSS (unsafe_get_pss t)
  | T.CKM_SHA1_RSA_PKCS -> CKM_SHA1_RSA_PKCS
  | T.CKM_SHA224_RSA_PKCS -> CKM_SHA224_RSA_PKCS
  | T.CKM_SHA256_RSA_PKCS -> CKM_SHA256_RSA_PKCS
  | T.CKM_SHA384_RSA_PKCS -> CKM_SHA384_RSA_PKCS
  | T.CKM_SHA512_RSA_PKCS -> CKM_SHA512_RSA_PKCS
  | T.CKM_SHA1_RSA_PKCS_PSS -> CKM_SHA1_RSA_PKCS_PSS (unsafe_get_pss t)
  | T.CKM_SHA224_RSA_PKCS_PSS -> CKM_SHA224_RSA_PKCS_PSS (unsafe_get_pss t)
  | T.CKM_SHA256_RSA_PKCS_PSS -> CKM_SHA256_RSA_PKCS_PSS (unsafe_get_pss t)
  | T.CKM_SHA384_RSA_PKCS_PSS -> CKM_SHA384_RSA_PKCS_PSS (unsafe_get_pss t)
  | T.CKM_SHA512_RSA_PKCS_PSS -> CKM_SHA512_RSA_PKCS_PSS (unsafe_get_pss t)
  | T.CKM_AES_KEY_GEN -> CKM_AES_KEY_GEN
  | T.CKM_AES_ECB -> CKM_AES_ECB
  | T.CKM_AES_CBC -> CKM_AES_CBC (unsafe_get_string t)
  | T.CKM_AES_CBC_PAD -> CKM_AES_CBC_PAD (unsafe_get_string t)
  | T.CKM_AES_MAC -> CKM_AES_MAC
  | T.CKM_AES_MAC_GENERAL -> CKM_AES_MAC_GENERAL (unsafe_get_ulong t)
  | T.CKM_AES_ECB_ENCRYPT_DATA ->
    CKM_AES_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  | T.CKM_AES_CBC_ENCRYPT_DATA ->
    CKM_AES_CBC_ENCRYPT_DATA (unsafe_get_aes_cbc_param t)
  | T.CKM_DES_KEY_GEN -> CKM_DES_KEY_GEN
  | T.CKM_DES_ECB -> CKM_DES_ECB
  | T.CKM_DES_CBC -> CKM_DES_CBC (unsafe_get_string t)
  | T.CKM_DES_CBC_PAD -> CKM_DES_CBC_PAD (unsafe_get_string t)
  | T.CKM_DES_MAC -> CKM_DES_MAC
  | T.CKM_DES_MAC_GENERAL -> CKM_DES_MAC_GENERAL (unsafe_get_ulong t)
  | T.CKM_DES_ECB_ENCRYPT_DATA ->
    CKM_DES_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  | T.CKM_DES_CBC_ENCRYPT_DATA ->
    CKM_DES_CBC_ENCRYPT_DATA (unsafe_get_des_cbc_param t)
  | T.CKM_DES3_KEY_GEN -> CKM_DES3_KEY_GEN
  | T.CKM_DES3_ECB -> CKM_DES3_ECB
  | T.CKM_DES3_CBC -> CKM_DES3_CBC (unsafe_get_string t)
  | T.CKM_DES3_CBC_PAD -> CKM_DES3_CBC_PAD (unsafe_get_string t)
  | T.CKM_DES3_MAC -> CKM_DES3_MAC
  | T.CKM_DES3_MAC_GENERAL -> CKM_DES3_MAC_GENERAL (unsafe_get_ulong t)
  | T.CKM_DES3_ECB_ENCRYPT_DATA ->
    CKM_DES3_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  | T.CKM_DES3_CBC_ENCRYPT_DATA ->
    CKM_DES3_CBC_ENCRYPT_DATA (unsafe_get_des_cbc_param t)
  | T.CKM_CONCATENATE_BASE_AND_DATA ->
    CKM_CONCATENATE_BASE_AND_DATA (unsafe_get_derivation_string t)
  | T.CKM_CONCATENATE_DATA_AND_BASE ->
    CKM_CONCATENATE_DATA_AND_BASE (unsafe_get_derivation_string t)
  | T.CKM_XOR_BASE_AND_DATA ->
    CKM_XOR_BASE_AND_DATA (unsafe_get_derivation_string t)
  | T.CKM_EXTRACT_KEY_FROM_KEY -> CKM_EXTRACT_KEY_FROM_KEY (unsafe_get_ulong t)
  | T.CKM_CONCATENATE_BASE_AND_KEY ->
    CKM_CONCATENATE_BASE_AND_KEY (unsafe_get_ulong t)
  | T.CKM_EC_KEY_PAIR_GEN -> CKM_EC_KEY_PAIR_GEN
  | T.CKM_ECDSA -> CKM_ECDSA
  | T.CKM_ECDSA_SHA1 -> CKM_ECDSA_SHA1
  | T.CKM_ECDH1_DERIVE -> CKM_ECDH1_DERIVE (unsafe_get_ecdh1_derive_param t)
  | T.CKM_ECDH1_COFACTOR_DERIVE ->
    CKM_ECDH1_COFACTOR_DERIVE (unsafe_get_ecdh1_derive_param t)
  | T.CKM_ECMQV_DERIVE -> CKM_ECMQV_DERIVE (unsafe_get_ecmqv_derive_param t)
  | T.CKM_DSA_KEY_PAIR_GEN -> CKM_DSA_KEY_PAIR_GEN
  | T.CKM_DSA_SHA1 -> CKM_DSA_SHA1
  | T.CKM_DSA_SHA224 -> CKM_DSA_SHA224
  | T.CKM_DSA_SHA256 -> CKM_DSA_SHA256
  | T.CKM_DSA_SHA384 -> CKM_DSA_SHA384
  | T.CKM_DSA_SHA512 -> CKM_DSA_SHA512
  | T.CKM_AES_CTR ->
    let param =
      unsafe_get_struct t Pkcs11_CK_AES_CTR_PARAMS.t
        Pkcs11_CK_AES_CTR_PARAMS.view
    in
    CKM_AES_CTR param
  | T.CKM_AES_GCM ->
    let params =
      unsafe_get_struct t Pkcs11_CK_GCM_PARAMS.t Pkcs11_CK_GCM_PARAMS.view
    in
    CKM_AES_GCM params
  | T.CKM_AES_KEY_WRAP ->
    let params = unsafe_get_aes_key_wrap_option t in
    CKM_AES_KEY_WRAP params
  | T.CKM_SHA_1_HMAC -> CKM_SHA_1_HMAC
  | T.CKM_SHA224_HMAC -> CKM_SHA224_HMAC
  | T.CKM_SHA256_HMAC -> CKM_SHA256_HMAC
  | T.CKM_SHA384_HMAC -> CKM_SHA384_HMAC
  | T.CKM_SHA512_HMAC -> CKM_SHA512_HMAC
  | T.CKM_ECDSA_SHA224 -> CKM_ECDSA_SHA224
  | T.CKM_ECDSA_SHA256 -> CKM_ECDSA_SHA256
  | T.CKM_ECDSA_SHA384 -> CKM_ECDSA_SHA384
  | T.CKM_ECDSA_SHA512 -> CKM_ECDSA_SHA512
  | T.CKM_GENERIC_SECRET_KEY_GEN -> CKM_GENERIC_SECRET_KEY_GEN
  | T.CKM_RSA_9796
  | T.CKM_MD2_RSA_PKCS
  | T.CKM_MD5_RSA_PKCS
  | T.CKM_RIPEMD128_RSA_PKCS
  | T.CKM_RIPEMD160_RSA_PKCS
  | T.CKM_RSA_X9_31
  | T.CKM_SHA1_RSA_X9_31
  | T.CKM_DSA
  | T.CKM_DH_PKCS_KEY_PAIR_GEN
  | T.CKM_DH_PKCS_DERIVE
  | T.CKM_X9_42_DH_KEY_PAIR_GEN
  | T.CKM_X9_42_DH_DERIVE
  | T.CKM_X9_42_DH_HYBRID_DERIVE
  | T.CKM_X9_42_MQV_DERIVE
  | T.CKM_RC2_KEY_GEN
  | T.CKM_RC2_ECB
  | T.CKM_RC2_CBC
  | T.CKM_RC2_MAC
  | T.CKM_RC2_MAC_GENERAL
  | T.CKM_RC2_CBC_PAD
  | T.CKM_RC4_KEY_GEN
  | T.CKM_RC4
  | T.CKM_DES2_KEY_GEN
  | T.CKM_CDMF_KEY_GEN
  | T.CKM_CDMF_ECB
  | T.CKM_CDMF_CBC
  | T.CKM_CDMF_MAC
  | T.CKM_CDMF_MAC_GENERAL
  | T.CKM_CDMF_CBC_PAD
  | T.CKM_DES_OFB64
  | T.CKM_DES_OFB8
  | T.CKM_DES_CFB64
  | T.CKM_DES_CFB8
  | T.CKM_MD2
  | T.CKM_MD2_HMAC
  | T.CKM_MD2_HMAC_GENERAL
  | T.CKM_MD5_HMAC
  | T.CKM_MD5_HMAC_GENERAL
  | T.CKM_SHA_1_HMAC_GENERAL
  | T.CKM_RIPEMD128
  | T.CKM_RIPEMD128_HMAC
  | T.CKM_RIPEMD128_HMAC_GENERAL
  | T.CKM_RIPEMD160
  | T.CKM_RIPEMD160_HMAC
  | T.CKM_RIPEMD160_HMAC_GENERAL
  | T.CKM_SHA256_HMAC_GENERAL
  | T.CKM_SHA224_HMAC_GENERAL
  | T.CKM_SHA384_HMAC_GENERAL
  | T.CKM_SHA512_HMAC_GENERAL
  | T.CKM_SECURID_KEY_GEN
  | T.CKM_SECURID
  | T.CKM_HOTP_KEY_GEN
  | T.CKM_HOTP
  | T.CKM_ACTI
  | T.CKM_ACTI_KEY_GEN
  | T.CKM_CAST_KEY_GEN
  | T.CKM_CAST_ECB
  | T.CKM_CAST_CBC
  | T.CKM_CAST_MAC
  | T.CKM_CAST_MAC_GENERAL
  | T.CKM_CAST_CBC_PAD
  | T.CKM_CAST3_KEY_GEN
  | T.CKM_CAST3_ECB
  | T.CKM_CAST3_CBC
  | T.CKM_CAST3_MAC
  | T.CKM_CAST3_MAC_GENERAL
  | T.CKM_CAST3_CBC_PAD
  | T.CKM_CAST128_KEY_GEN
  | T.CKM_CAST128_ECB
  | T.CKM_CAST128_CBC
  | T.CKM_CAST128_MAC
  | T.CKM_CAST128_MAC_GENERAL
  | T.CKM_CAST128_CBC_PAD
  | T.CKM_RC5_KEY_GEN
  | T.CKM_RC5_ECB
  | T.CKM_RC5_CBC
  | T.CKM_RC5_MAC
  | T.CKM_RC5_MAC_GENERAL
  | T.CKM_RC5_CBC_PAD
  | T.CKM_IDEA_KEY_GEN
  | T.CKM_IDEA_ECB
  | T.CKM_IDEA_CBC
  | T.CKM_IDEA_MAC
  | T.CKM_IDEA_MAC_GENERAL
  | T.CKM_IDEA_CBC_PAD
  | T.CKM_SSL3_PRE_MASTER_KEY_GEN
  | T.CKM_SSL3_MASTER_KEY_DERIVE
  | T.CKM_SSL3_KEY_AND_MAC_DERIVE
  | T.CKM_SSL3_MASTER_KEY_DERIVE_DH
  | T.CKM_TLS_PRE_MASTER_KEY_GEN
  | T.CKM_TLS_MASTER_KEY_DERIVE
  | T.CKM_TLS_KEY_AND_MAC_DERIVE
  | T.CKM_TLS_MASTER_KEY_DERIVE_DH
  | T.CKM_TLS_PRF
  | T.CKM_SSL3_MD5_MAC
  | T.CKM_SSL3_SHA1_MAC
  | T.CKM_MD5_KEY_DERIVATION
  | T.CKM_MD2_KEY_DERIVATION
  | T.CKM_SHA1_KEY_DERIVATION
  | T.CKM_SHA256_KEY_DERIVATION
  | T.CKM_SHA384_KEY_DERIVATION
  | T.CKM_SHA512_KEY_DERIVATION
  | T.CKM_SHA224_KEY_DERIVATION
  | T.CKM_PBE_MD2_DES_CBC
  | T.CKM_PBE_MD5_DES_CBC
  | T.CKM_PBE_MD5_CAST_CBC
  | T.CKM_PBE_MD5_CAST3_CBC
  | T.CKM_PBE_MD5_CAST128_CBC
  | T.CKM_PBE_SHA1_CAST128_CBC
  | T.CKM_PBE_SHA1_RC4_128
  | T.CKM_PBE_SHA1_RC4_40
  | T.CKM_PBE_SHA1_DES3_EDE_CBC
  | T.CKM_PBE_SHA1_DES2_EDE_CBC
  | T.CKM_PBE_SHA1_RC2_128_CBC
  | T.CKM_PBE_SHA1_RC2_40_CBC
  | T.CKM_PKCS5_PBKD2
  | T.CKM_PBA_SHA1_WITH_SHA1_HMAC
  | T.CKM_WTLS_PRE_MASTER_KEY_GEN
  | T.CKM_WTLS_MASTER_KEY_DERIVE
  | T.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
  | T.CKM_WTLS_PRF
  | T.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
  | T.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
  | T.CKM_KEY_WRAP_LYNKS
  | T.CKM_KEY_WRAP_SET_OAEP
  | T.CKM_CMS_SIG
  | T.CKM_KIP_DERIVE
  | T.CKM_KIP_WRAP
  | T.CKM_KIP_MAC
  | T.CKM_CAMELLIA_KEY_GEN
  | T.CKM_CAMELLIA_ECB
  | T.CKM_CAMELLIA_CBC
  | T.CKM_CAMELLIA_MAC
  | T.CKM_CAMELLIA_MAC_GENERAL
  | T.CKM_CAMELLIA_CBC_PAD
  | T.CKM_CAMELLIA_ECB_ENCRYPT_DATA
  | T.CKM_CAMELLIA_CBC_ENCRYPT_DATA
  | T.CKM_CAMELLIA_CTR
  | T.CKM_ARIA_KEY_GEN
  | T.CKM_ARIA_ECB
  | T.CKM_ARIA_CBC
  | T.CKM_ARIA_MAC
  | T.CKM_ARIA_MAC_GENERAL
  | T.CKM_ARIA_CBC_PAD
  | T.CKM_ARIA_ECB_ENCRYPT_DATA
  | T.CKM_ARIA_CBC_ENCRYPT_DATA
  | T.CKM_SKIPJACK_KEY_GEN
  | T.CKM_SKIPJACK_ECB64
  | T.CKM_SKIPJACK_CBC64
  | T.CKM_SKIPJACK_OFB64
  | T.CKM_SKIPJACK_CFB64
  | T.CKM_SKIPJACK_CFB32
  | T.CKM_SKIPJACK_CFB16
  | T.CKM_SKIPJACK_CFB8
  | T.CKM_SKIPJACK_WRAP
  | T.CKM_SKIPJACK_PRIVATE_WRAP
  | T.CKM_SKIPJACK_RELAYX
  | T.CKM_KEA_KEY_PAIR_GEN
  | T.CKM_KEA_KEY_DERIVE
  | T.CKM_FORTEZZA_TIMESTAMP
  | T.CKM_BATON_KEY_GEN
  | T.CKM_BATON_ECB128
  | T.CKM_BATON_ECB96
  | T.CKM_BATON_CBC128
  | T.CKM_BATON_COUNTER
  | T.CKM_BATON_SHUFFLE
  | T.CKM_BATON_WRAP
  | T.CKM_JUNIPER_KEY_GEN
  | T.CKM_JUNIPER_ECB128
  | T.CKM_JUNIPER_CBC128
  | T.CKM_JUNIPER_COUNTER
  | T.CKM_JUNIPER_SHUFFLE
  | T.CKM_JUNIPER_WRAP
  | T.CKM_FASTHASH
  | T.CKM_BLOWFISH_KEY_GEN
  | T.CKM_BLOWFISH_CBC
  | T.CKM_TWOFISH_KEY_GEN
  | T.CKM_TWOFISH_CBC
  | T.CKM_DSA_PARAMETER_GEN
  | T.CKM_DH_PKCS_PARAMETER_GEN
  | T.CKM_X9_42_DH_PARAMETER_GEN
  | T.CKM_GOSTR3410_KEY_PAIR_GEN
  | T.CKM_GOSTR3410
  | T.CKM_GOSTR3410_WITH_GOSTR3411
  | T.CKM_GOSTR3411
  | T.CKM_GOSTR3411_HMAC
  | T.CKM_AES_CCM
  | T.CKM_AES_CFB1
  | T.CKM_AES_CFB128
  | T.CKM_AES_CFB64
  | T.CKM_AES_CFB8
  | T.CKM_AES_CMAC
  | T.CKM_AES_CMAC_GENERAL
  | T.CKM_AES_CTS
  | T.CKM_AES_GMAC
  | T.CKM_AES_KEY_WRAP_PAD
  | T.CKM_AES_OFB
  | T.CKM_AES_XCBC_MAC
  | T.CKM_AES_XCBC_MAC_96
  | T.CKM_BLOWFISH_CBC_PAD
  | T.CKM_DES3_CMAC
  | T.CKM_DES3_CMAC_GENERAL
  | T.CKM_DSA_PROBABLISTIC_PARAMETER_GEN
  | T.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
  | T.CKM_ECDH_AES_KEY_WRAP
  | T.CKM_GOST28147
  | T.CKM_GOST28147_ECB
  | T.CKM_GOST28147_KEY_GEN
  | T.CKM_GOST28147_KEY_WRAP
  | T.CKM_GOST28147_MAC
  | T.CKM_GOSTR3410_DERIVE
  | T.CKM_GOSTR3410_KEY_WRAP
  | T.CKM_KEA_DERIVE
  | T.CKM_RSA_AES_KEY_WRAP
  | T.CKM_RSA_PKCS_OAEP_TPM_1_1
  | T.CKM_RSA_PKCS_TPM_1_1
  | T.CKM_SEED_CBC
  | T.CKM_SEED_CBC_ENCRYPT_DATA
  | T.CKM_SEED_CBC_PAD
  | T.CKM_SEED_ECB
  | T.CKM_SEED_ECB_ENCRYPT_DATA
  | T.CKM_SEED_KEY_GEN
  | T.CKM_SEED_MAC
  | T.CKM_SEED_MAC_GENERAL
  | T.CKM_SHA512_224
  | T.CKM_SHA512_224_HMAC
  | T.CKM_SHA512_224_HMAC_GENERAL
  | T.CKM_SHA512_224_KEY_DERIVATION
  | T.CKM_SHA512_256
  | T.CKM_SHA512_256_HMAC
  | T.CKM_SHA512_256_HMAC_GENERAL
  | T.CKM_SHA512_256_KEY_DERIVATION
  | T.CKM_SHA512_T
  | T.CKM_SHA512_T_HMAC
  | T.CKM_SHA512_T_HMAC_GENERAL
  | T.CKM_SHA512_T_KEY_DERIVATION
  | T.CKM_TLS10_MAC_CLIENT
  | T.CKM_TLS10_MAC_SERVER
  | T.CKM_TLS12_KDF
  | T.CKM_TLS12_KEY_AND_MAC_DERIVE
  | T.CKM_TLS12_KEY_SAFE_DERIVE
  | T.CKM_TLS12_MAC
  | T.CKM_TLS12_MASTER_KEY_DERIVE
  | T.CKM_TLS12_MASTER_KEY_DERIVE_DH
  | T.CKM_TLS_KDF
  | T.CKM_TLS_MAC
  | T.CKM_TWOFISH_CBC_PAD
  | T.CKM_VENDOR_DEFINED
  | T.CKM_CS_UNKNOWN _ ->
    CKM_CS_UNKNOWN ul
