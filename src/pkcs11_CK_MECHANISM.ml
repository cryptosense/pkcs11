open Ctypes
open Ctypes_helpers

type _t

type t = _t structure

let ck_mechanism : t typ = structure "CK_MECHANISM"

let (-:) ty label = smart_field ck_mechanism label ty
let mechanism = Pkcs11_CK_MECHANISM_TYPE.typ -: "mechanism"
let parameter = Reachable_ptr.typ void -: "pParameter"
let parameter_len = ulong -: "pParameterLen"
let () = seal ck_mechanism

(* user type *)

type u =
  | CKM_SHA_1
  | CKM_SHA224
  | CKM_SHA256
  | CKM_SHA512
  | CKM_MD5
  | CKM_RSA_PKCS_KEY_PAIR_GEN
  | CKM_RSA_X9_31_KEY_PAIR_GEN
  | CKM_RSA_PKCS
  | CKM_RSA_PKCS_OAEP of P11_rsa_pkcs_oaep_params.t
  | CKM_RSA_X_509
  | CKM_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA1_RSA_PKCS
  | CKM_SHA224_RSA_PKCS
  | CKM_SHA256_RSA_PKCS
  | CKM_SHA384_RSA_PKCS
  | CKM_SHA512_RSA_PKCS
  | CKM_SHA1_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA224_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA256_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA384_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA512_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_AES_KEY_GEN
  | CKM_AES_ECB
  | CKM_AES_CBC of string
  | CKM_AES_CBC_PAD of string
  | CKM_AES_MAC
  | CKM_AES_MAC_GENERAL of Pkcs11_CK_ULONG.t
  | CKM_AES_ECB_ENCRYPT_DATA of Pkcs11_CK_KEY_DERIVATION_STRING_DATA.u
  | CKM_AES_CBC_ENCRYPT_DATA of P11_aes_cbc_encrypt_data_params.t
  | CKM_DES_KEY_GEN
  | CKM_DES_ECB
  | CKM_DES_CBC of string
  | CKM_DES_CBC_PAD of string
  | CKM_DES_MAC
  | CKM_DES_MAC_GENERAL of Pkcs11_CK_ULONG.t
  | CKM_DES_ECB_ENCRYPT_DATA of Pkcs11_CK_KEY_DERIVATION_STRING_DATA.u
  | CKM_DES_CBC_ENCRYPT_DATA of P11_des_cbc_encrypt_data_params.t
  | CKM_DES3_KEY_GEN
  | CKM_DES3_ECB
  | CKM_DES3_CBC of string
  | CKM_DES3_CBC_PAD of string
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL of Pkcs11_CK_ULONG.t
  | CKM_DES3_ECB_ENCRYPT_DATA of Pkcs11_CK_KEY_DERIVATION_STRING_DATA.u
  | CKM_DES3_CBC_ENCRYPT_DATA of P11_des_cbc_encrypt_data_params.t
  | CKM_CONCATENATE_BASE_AND_DATA of Pkcs11_CK_KEY_DERIVATION_STRING_DATA.u
  | CKM_CONCATENATE_DATA_AND_BASE of Pkcs11_CK_KEY_DERIVATION_STRING_DATA.u
  | CKM_XOR_BASE_AND_DATA of Pkcs11_CK_KEY_DERIVATION_STRING_DATA.u
  | CKM_EXTRACT_KEY_FROM_KEY of Pkcs11_CK_ULONG.t
  | CKM_CONCATENATE_BASE_AND_KEY of Pkcs11_CK_OBJECT_HANDLE.t
  | CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA
  | CKM_ECDSA_SHA1
  | CKM_ECDH1_DERIVE of Pkcs11_CK_ECDH1_DERIVE_PARAMS.u
  | CKM_ECDH1_COFACTOR_DERIVE of Pkcs11_CK_ECDH1_DERIVE_PARAMS.u
  | CKM_ECMQV_DERIVE of Pkcs11_CK_ECMQV_DERIVE_PARAMS.u
  | CKM_PKCS5_PBKD2 of P11_pkcs5_pbkd2_data_params.t
  | CKM_CS_UNKNOWN of Pkcs11_CK_RAW_PAYLOAD.t

let make: u -> t =
  let make ckm param param_len =
    let open Ctypes in
    let m = make ck_mechanism in
    setf m mechanism ckm;
    Reachable_ptr.setf m parameter param;
    setf m parameter_len param_len;
    m
  in
  let simple ckm = make ckm null Unsigned.ULong.zero in
  let struct_ ckm params ctype make_ctype =
    let params = make_ctype params in
    make ckm (to_voidp (addr params)) (sizeof ctype |> Unsigned.ULong.of_int)
  in
  let pss ckm params =
    struct_ ckm params Pkcs11_CK_RSA_PKCS_PSS_PARAMS.t Pkcs11_CK_RSA_PKCS_PSS_PARAMS.make
  in
  let string ckm param =
    let params = Pkcs11_data.of_string param in
    let char_ptr = Pkcs11_data.get_content params in
    let param_len = Pkcs11_data.get_length params in
    make ckm (to_voidp char_ptr) param_len
  in
  let derivation_string ckm param =
    struct_ ckm param
      Pkcs11_CK_KEY_DERIVATION_STRING_DATA.t Pkcs11_CK_KEY_DERIVATION_STRING_DATA.make
  in
  let ulong ckm param =
    let ptr = allocate ulong param in
    make ckm (to_voidp ptr) (Unsigned.ULong.of_int (sizeof ulong))
  in
  let open Pkcs11_CK_MECHANISM_TYPE in
  function
    | CKM_SHA_1 ->
        simple _CKM_SHA_1
    | CKM_SHA224 ->
        simple _CKM_SHA224
    | CKM_SHA256 ->
        simple _CKM_SHA256
    | CKM_SHA512 ->
        simple _CKM_SHA512
    | CKM_MD5 ->
        simple _CKM_MD5
    | CKM_RSA_PKCS_KEY_PAIR_GEN ->
        simple _CKM_RSA_PKCS_KEY_PAIR_GEN
    | CKM_RSA_X9_31_KEY_PAIR_GEN ->
        simple _CKM_RSA_X9_31_KEY_PAIR_GEN
    | CKM_RSA_PKCS ->
        simple _CKM_RSA_PKCS
    | CKM_RSA_PKCS_OAEP p ->
        struct_ _CKM_RSA_PKCS_OAEP p Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.t
          Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.make
    | CKM_RSA_X_509 ->
        simple _CKM_RSA_X_509
    | CKM_RSA_PKCS_PSS p ->
        pss _CKM_RSA_PKCS_PSS p
    | CKM_SHA1_RSA_PKCS ->
        simple _CKM_SHA1_RSA_PKCS
    | CKM_SHA224_RSA_PKCS ->
        simple _CKM_SHA224_RSA_PKCS
    | CKM_SHA256_RSA_PKCS ->
        simple _CKM_SHA256_RSA_PKCS
    | CKM_SHA384_RSA_PKCS ->
        simple _CKM_SHA384_RSA_PKCS
    | CKM_SHA512_RSA_PKCS ->
        simple _CKM_SHA512_RSA_PKCS
    | CKM_SHA1_RSA_PKCS_PSS p ->
        pss _CKM_SHA1_RSA_PKCS_PSS p
    | CKM_SHA224_RSA_PKCS_PSS p ->
        pss _CKM_SHA224_RSA_PKCS_PSS p
    | CKM_SHA256_RSA_PKCS_PSS p ->
        pss _CKM_SHA256_RSA_PKCS_PSS p
    | CKM_SHA384_RSA_PKCS_PSS p ->
        pss _CKM_SHA384_RSA_PKCS_PSS p
    | CKM_SHA512_RSA_PKCS_PSS p ->
        pss _CKM_SHA512_RSA_PKCS_PSS p
    | CKM_AES_KEY_GEN ->
        simple _CKM_AES_KEY_GEN
    | CKM_AES_ECB ->
        simple _CKM_AES_ECB
    | CKM_AES_CBC p ->
        string _CKM_AES_CBC p
    | CKM_AES_CBC_PAD p ->
        string _CKM_AES_CBC_PAD p
    | CKM_AES_MAC ->
        simple _CKM_AES_MAC
    | CKM_AES_MAC_GENERAL p ->
        ulong _CKM_AES_MAC_GENERAL p
    | CKM_AES_ECB_ENCRYPT_DATA p ->
        derivation_string _CKM_AES_ECB_ENCRYPT_DATA p
    | CKM_AES_CBC_ENCRYPT_DATA p ->
        struct_ _CKM_AES_CBC_ENCRYPT_DATA p Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.t
          Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.make
    | CKM_DES_KEY_GEN ->
        simple _CKM_DES_KEY_GEN
    | CKM_DES_ECB ->
        simple _CKM_DES_ECB
    | CKM_DES_CBC p ->
        string _CKM_DES_CBC p
    | CKM_DES_CBC_PAD p ->
        string _CKM_DES_CBC_PAD p
    | CKM_DES_MAC ->
        simple _CKM_DES_MAC
    | CKM_DES_MAC_GENERAL p ->
        ulong _CKM_DES_MAC_GENERAL p
    | CKM_DES_ECB_ENCRYPT_DATA p ->
        derivation_string _CKM_DES_ECB_ENCRYPT_DATA p
    | CKM_DES_CBC_ENCRYPT_DATA p ->
        struct_ _CKM_DES_CBC_ENCRYPT_DATA p Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.t
          Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.make
    | CKM_DES3_KEY_GEN ->
        simple _CKM_DES3_KEY_GEN
    | CKM_DES3_ECB ->
        simple _CKM_DES3_ECB
    | CKM_DES3_CBC p ->
        string _CKM_DES3_CBC p
    | CKM_DES3_CBC_PAD p ->
        string _CKM_DES3_CBC_PAD p
    | CKM_DES3_MAC ->
        simple _CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL p ->
        ulong _CKM_DES3_MAC_GENERAL p
    | CKM_DES3_ECB_ENCRYPT_DATA p ->
        derivation_string _CKM_DES3_ECB_ENCRYPT_DATA p
    | CKM_DES3_CBC_ENCRYPT_DATA p ->
        struct_ _CKM_DES3_CBC_ENCRYPT_DATA p Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.t
          Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.make
    | CKM_CONCATENATE_BASE_AND_DATA p ->
        derivation_string _CKM_CONCATENATE_BASE_AND_DATA p
    | CKM_CONCATENATE_DATA_AND_BASE p ->
        derivation_string _CKM_CONCATENATE_DATA_AND_BASE p
    | CKM_XOR_BASE_AND_DATA p ->
        derivation_string _CKM_XOR_BASE_AND_DATA p
    | CKM_EXTRACT_KEY_FROM_KEY p ->
        ulong _CKM_EXTRACT_KEY_FROM_KEY p
    | CKM_CONCATENATE_BASE_AND_KEY p ->
        ulong _CKM_CONCATENATE_BASE_AND_KEY p
    | CKM_EC_KEY_PAIR_GEN ->
        simple _CKM_EC_KEY_PAIR_GEN
    | CKM_ECDSA ->
        simple _CKM_ECDSA
    | CKM_ECDSA_SHA1 ->
        simple _CKM_ECDSA_SHA1
    | CKM_ECDH1_DERIVE p ->
        struct_ _CKM_ECDH1_DERIVE p Pkcs11_CK_ECDH1_DERIVE_PARAMS.t
          Pkcs11_CK_ECDH1_DERIVE_PARAMS.make
    | CKM_ECDH1_COFACTOR_DERIVE p ->
        struct_ _CKM_ECDH1_COFACTOR_DERIVE p Pkcs11_CK_ECDH1_DERIVE_PARAMS.t
          Pkcs11_CK_ECDH1_DERIVE_PARAMS.make
    | CKM_ECMQV_DERIVE p ->
        struct_ _CKM_ECMQV_DERIVE p Pkcs11_CK_ECMQV_DERIVE_PARAMS.t
          Pkcs11_CK_ECMQV_DERIVE_PARAMS.make
    | CKM_PKCS5_PBKD2 p ->
        struct_ _CKM_PKCS5_PBKD2 p Pkcs11_CK_PKCS5_PBKD2_PARAMS.t
          Pkcs11_CK_PKCS5_PBKD2_PARAMS.make
    | CKM_CS_UNKNOWN (ckm, param) ->
        string ckm param

let mechanism_type m =
  let module T = P11_mechanism_type in
  match m with
    | CKM_SHA_1 -> T.CKM_SHA_1
    | CKM_SHA224 -> T.CKM_SHA224
    | CKM_SHA256 -> T.CKM_SHA256
    | CKM_SHA512 -> T.CKM_SHA512
    | CKM_MD5 -> T.CKM_MD5
    | CKM_RSA_PKCS_KEY_PAIR_GEN -> T.CKM_RSA_PKCS_KEY_PAIR_GEN
    | CKM_RSA_X9_31_KEY_PAIR_GEN -> T.CKM_RSA_X9_31_KEY_PAIR_GEN
    | CKM_RSA_PKCS -> T.CKM_RSA_PKCS
    | CKM_RSA_PKCS_OAEP _ -> T.CKM_RSA_PKCS_OAEP
    | CKM_RSA_X_509 -> T.CKM_RSA_X_509
    | CKM_RSA_PKCS_PSS _ -> T.CKM_RSA_PKCS_PSS
    | CKM_SHA1_RSA_PKCS -> T.CKM_SHA1_RSA_PKCS
    | CKM_SHA224_RSA_PKCS -> T.CKM_SHA224_RSA_PKCS
    | CKM_SHA256_RSA_PKCS -> T.CKM_SHA256_RSA_PKCS
    | CKM_SHA384_RSA_PKCS -> T.CKM_SHA384_RSA_PKCS
    | CKM_SHA512_RSA_PKCS -> T.CKM_SHA512_RSA_PKCS
    | CKM_SHA1_RSA_PKCS_PSS _ -> T.CKM_SHA1_RSA_PKCS_PSS
    | CKM_SHA224_RSA_PKCS_PSS _ -> T.CKM_SHA224_RSA_PKCS_PSS
    | CKM_SHA256_RSA_PKCS_PSS _ -> T.CKM_SHA256_RSA_PKCS_PSS
    | CKM_SHA384_RSA_PKCS_PSS _ -> T.CKM_SHA384_RSA_PKCS_PSS
    | CKM_SHA512_RSA_PKCS_PSS _ -> T.CKM_SHA512_RSA_PKCS_PSS
    | CKM_AES_KEY_GEN -> T.CKM_AES_KEY_GEN
    | CKM_AES_ECB -> T.CKM_AES_ECB
    | CKM_AES_CBC _ -> T.CKM_AES_CBC
    | CKM_AES_CBC_PAD _ -> T.CKM_AES_CBC_PAD
    | CKM_AES_MAC -> T.CKM_AES_MAC
    | CKM_AES_MAC_GENERAL _ -> T.CKM_AES_MAC_GENERAL
    | CKM_AES_ECB_ENCRYPT_DATA _ -> T.CKM_AES_ECB_ENCRYPT_DATA
    | CKM_AES_CBC_ENCRYPT_DATA _ -> T.CKM_AES_CBC_ENCRYPT_DATA
    | CKM_DES_KEY_GEN -> T.CKM_DES_KEY_GEN
    | CKM_DES_ECB -> T.CKM_DES_ECB
    | CKM_DES_CBC _ -> T.CKM_DES_CBC
    | CKM_DES_CBC_PAD _ -> T.CKM_DES_CBC_PAD
    | CKM_DES_MAC -> T.CKM_DES_MAC
    | CKM_DES_MAC_GENERAL _ -> T.CKM_DES_MAC_GENERAL
    | CKM_DES_ECB_ENCRYPT_DATA _ -> T.CKM_DES_ECB_ENCRYPT_DATA
    | CKM_DES_CBC_ENCRYPT_DATA _ -> T.CKM_DES_CBC_ENCRYPT_DATA
    | CKM_DES3_KEY_GEN -> T.CKM_DES3_KEY_GEN
    | CKM_DES3_ECB -> T.CKM_DES3_ECB
    | CKM_DES3_CBC _ -> T.CKM_DES3_CBC
    | CKM_DES3_CBC_PAD _ -> T.CKM_DES3_CBC_PAD
    | CKM_DES3_MAC -> T.CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL _ -> T.CKM_DES3_MAC_GENERAL
    | CKM_DES3_ECB_ENCRYPT_DATA _ -> T.CKM_DES3_ECB_ENCRYPT_DATA
    | CKM_DES3_CBC_ENCRYPT_DATA _ -> T.CKM_DES3_CBC_ENCRYPT_DATA
    | CKM_CONCATENATE_BASE_AND_DATA _ -> T.CKM_CONCATENATE_BASE_AND_DATA
    | CKM_CONCATENATE_DATA_AND_BASE _ -> T.CKM_CONCATENATE_DATA_AND_BASE
    | CKM_XOR_BASE_AND_DATA _ -> T.CKM_XOR_BASE_AND_DATA
    | CKM_EXTRACT_KEY_FROM_KEY _ -> T.CKM_EXTRACT_KEY_FROM_KEY
    | CKM_CONCATENATE_BASE_AND_KEY _ -> T.CKM_CONCATENATE_BASE_AND_KEY
    | CKM_EC_KEY_PAIR_GEN -> T.CKM_EC_KEY_PAIR_GEN
    | CKM_ECDSA -> T.CKM_ECDSA
    | CKM_ECDSA_SHA1 -> T.CKM_ECDSA_SHA1
    | CKM_ECDH1_DERIVE _ -> T.CKM_ECDH1_DERIVE
    | CKM_ECDH1_COFACTOR_DERIVE _ -> T.CKM_ECDH1_COFACTOR_DERIVE
    | CKM_ECMQV_DERIVE _ -> T.CKM_ECMQV_DERIVE
    | CKM_PKCS5_PBKD2 _ -> T.CKM_PKCS5_PBKD2
    | CKM_CS_UNKNOWN (ckm, _) -> T.CKM_CS_UNKNOWN ckm

let compare a b =
  let a_type = mechanism_type a in
  let b_type = mechanism_type b in
  let c = P11_mechanism_type.compare a_type b_type in
  if c <> 0 then
    c
  else
    match a, b with
      | CKM_RSA_PKCS_OAEP a_param, CKM_RSA_PKCS_OAEP b_param
        -> P11_rsa_pkcs_oaep_params.compare a_param b_param
      | CKM_PKCS5_PBKD2 a_param, CKM_PKCS5_PBKD2 b_param
        -> P11_pkcs5_pbkd2_data_params.compare a_param b_param
      | CKM_RSA_PKCS_PSS a_param, CKM_RSA_PKCS_PSS b_param
      | CKM_SHA1_RSA_PKCS_PSS a_param, CKM_SHA1_RSA_PKCS_PSS b_param
      | CKM_SHA224_RSA_PKCS_PSS a_param, CKM_SHA224_RSA_PKCS_PSS b_param
      | CKM_SHA256_RSA_PKCS_PSS a_param, CKM_SHA256_RSA_PKCS_PSS b_param
      | CKM_SHA384_RSA_PKCS_PSS a_param, CKM_SHA384_RSA_PKCS_PSS b_param
      | CKM_SHA512_RSA_PKCS_PSS a_param, CKM_SHA512_RSA_PKCS_PSS b_param
        -> P11_rsa_pkcs_pss_params.compare a_param b_param
      | CKM_AES_CBC a_param, CKM_AES_CBC b_param
      | CKM_AES_CBC_PAD a_param, CKM_AES_CBC_PAD b_param
      | CKM_DES_CBC a_param, CKM_DES_CBC b_param
      | CKM_DES_CBC_PAD a_param, CKM_DES_CBC_PAD b_param
      | CKM_DES3_CBC a_param, CKM_DES3_CBC b_param
      | CKM_DES3_CBC_PAD a_param, CKM_DES3_CBC_PAD b_param
      | CKM_AES_ECB_ENCRYPT_DATA a_param,
        CKM_AES_ECB_ENCRYPT_DATA b_param
      | CKM_DES_ECB_ENCRYPT_DATA a_param,
        CKM_DES_ECB_ENCRYPT_DATA b_param
      | CKM_DES3_ECB_ENCRYPT_DATA a_param,
        CKM_DES3_ECB_ENCRYPT_DATA b_param
      | CKM_CONCATENATE_BASE_AND_DATA a_param,
        CKM_CONCATENATE_BASE_AND_DATA b_param
      | CKM_CONCATENATE_DATA_AND_BASE a_param,
        CKM_CONCATENATE_DATA_AND_BASE b_param
      | CKM_XOR_BASE_AND_DATA a_param,
        CKM_XOR_BASE_AND_DATA b_param
        -> String.compare a_param b_param
      | CKM_AES_CBC_ENCRYPT_DATA a_param,
        CKM_AES_CBC_ENCRYPT_DATA b_param
        -> P11_aes_cbc_encrypt_data_params.compare a_param b_param
      | CKM_DES_CBC_ENCRYPT_DATA a_param,
        CKM_DES_CBC_ENCRYPT_DATA b_param
      | CKM_DES3_CBC_ENCRYPT_DATA a_param,
        CKM_DES3_CBC_ENCRYPT_DATA b_param
        -> P11_des_cbc_encrypt_data_params.compare a_param b_param
      | CKM_EXTRACT_KEY_FROM_KEY a_param,
        CKM_EXTRACT_KEY_FROM_KEY b_param
      | CKM_CONCATENATE_BASE_AND_KEY a_param,
        CKM_CONCATENATE_BASE_AND_KEY b_param
      | CKM_AES_MAC_GENERAL a_param,
        CKM_AES_MAC_GENERAL b_param
      | CKM_DES_MAC_GENERAL a_param,
        CKM_DES_MAC_GENERAL b_param
      | CKM_DES3_MAC_GENERAL a_param,
        CKM_DES3_MAC_GENERAL b_param
        -> Pkcs11_CK_ULONG.compare a_param b_param
      | CKM_CS_UNKNOWN a_param,
        CKM_CS_UNKNOWN b_param
          -> Pkcs11_CK_RAW_PAYLOAD.compare a_param b_param
      | CKM_ECDH1_DERIVE a_param,
        CKM_ECDH1_DERIVE b_param
      | CKM_ECDH1_COFACTOR_DERIVE a_param,
        CKM_ECDH1_COFACTOR_DERIVE b_param
        -> Pkcs11_CK_ECDH1_DERIVE_PARAMS.compare a_param b_param
      | CKM_ECMQV_DERIVE a_param,
        CKM_ECMQV_DERIVE b_param
        -> Pkcs11_CK_ECMQV_DERIVE_PARAMS.compare a_param b_param
      | CKM_RSA_PKCS_OAEP _, _
      | CKM_PKCS5_PBKD2 _, _
      | CKM_RSA_PKCS_PSS _, _
      | CKM_SHA1_RSA_PKCS_PSS _, _
      | CKM_SHA224_RSA_PKCS_PSS _, _
      | CKM_SHA256_RSA_PKCS_PSS _, _
      | CKM_SHA384_RSA_PKCS_PSS _, _
      | CKM_SHA512_RSA_PKCS_PSS _, _
      | CKM_AES_CBC _, _
      | CKM_AES_CBC_PAD _, _
      | CKM_DES_CBC _, _
      | CKM_DES_CBC_PAD _, _
      | CKM_DES3_CBC _, _
      | CKM_DES3_CBC_PAD _, _
      | CKM_AES_ECB_ENCRYPT_DATA _, _
      | CKM_DES_ECB_ENCRYPT_DATA _, _
      | CKM_DES3_ECB_ENCRYPT_DATA _, _
      | CKM_AES_CBC_ENCRYPT_DATA _, _
      | CKM_DES_CBC_ENCRYPT_DATA _, _
      | CKM_DES3_CBC_ENCRYPT_DATA _, _
      | CKM_CONCATENATE_BASE_AND_DATA _, _
      | CKM_CONCATENATE_DATA_AND_BASE _, _
      | CKM_XOR_BASE_AND_DATA _, _
      | CKM_EXTRACT_KEY_FROM_KEY _, _
      | CKM_CONCATENATE_BASE_AND_KEY _, _
      | CKM_AES_MAC_GENERAL _, _
      | CKM_DES_MAC_GENERAL _, _
      | CKM_DES3_MAC_GENERAL _, _
      | CKM_ECDH1_DERIVE _, _
      | CKM_ECDH1_COFACTOR_DERIVE _, _
      | CKM_ECMQV_DERIVE _, _
      | CKM_CS_UNKNOWN _, _
        (* Should have been covered by the comparison of mechanism types,
           or by the above cases. *)
        -> assert false
      | CKM_SHA_1, _
      | CKM_SHA224, _
      | CKM_SHA256, _
      | CKM_SHA512, _
      | CKM_MD5, _
      | CKM_RSA_PKCS_KEY_PAIR_GEN, _
      | CKM_RSA_X9_31_KEY_PAIR_GEN, _
      | CKM_RSA_PKCS, _
      | CKM_RSA_X_509, _
      | CKM_SHA1_RSA_PKCS, _
      | CKM_SHA224_RSA_PKCS, _
      | CKM_SHA256_RSA_PKCS, _
      | CKM_SHA384_RSA_PKCS, _
      | CKM_SHA512_RSA_PKCS, _
      | CKM_AES_KEY_GEN, _
      | CKM_AES_ECB, _
      | CKM_AES_MAC, _
      | CKM_DES_KEY_GEN, _
      | CKM_DES_ECB, _
      | CKM_DES_MAC, _
      | CKM_DES3_KEY_GEN, _
      | CKM_DES3_ECB, _
      | CKM_DES3_MAC, _
      | CKM_EC_KEY_PAIR_GEN, _
      | CKM_ECDSA, _
      | CKM_ECDSA_SHA1, _
        -> 0 (* Same mechanism types, no parameters. *)

let unsafe_get_string t =
  view_string t parameter_len parameter

let unsafe_get_struct t typ view =
  let p = from_voidp typ (Reachable_ptr.getf t parameter) in
  view (!@ p)

let unsafe_get_oaep t =
  unsafe_get_struct t Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.t Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.view

let unsafe_get_pss t =
  unsafe_get_struct t Pkcs11_CK_RSA_PKCS_PSS_PARAMS.t Pkcs11_CK_RSA_PKCS_PSS_PARAMS.view

let unsafe_get_derivation_string t =
  unsafe_get_struct t Pkcs11_CK_KEY_DERIVATION_STRING_DATA.t
    Pkcs11_CK_KEY_DERIVATION_STRING_DATA.view

let unsafe_get_aes_cbc_param t =
  unsafe_get_struct t Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.t
    Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS.view

let unsafe_get_des_cbc_param t =
  unsafe_get_struct t Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.t
    Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS.view

let unsafe_get_ecdh1_derive_param t =
  unsafe_get_struct t Pkcs11_CK_ECDH1_DERIVE_PARAMS.t
    Pkcs11_CK_ECDH1_DERIVE_PARAMS.view

let unsafe_get_ecmqv_derive_param t =
  unsafe_get_struct t Pkcs11_CK_ECMQV_DERIVE_PARAMS.t
    Pkcs11_CK_ECMQV_DERIVE_PARAMS.view

let unsafe_get_ulong t =
  let p =  Reachable_ptr.getf t parameter |> from_voidp ulong in
  !@ p

let view (t:t) : u =
  let ul = getf t mechanism in
  let open Pkcs11_CK_MECHANISM_TYPE in
  let (==) = fun a b ->
    let ua = Pkcs11_CK_MECHANISM_TYPE.view a in
    let ub = Pkcs11_CK_MECHANISM_TYPE.view b in
    P11_mechanism_type.equal ua ub
  in
  if ul == _CKM_SHA_1 then CKM_SHA_1
  else if ul == _CKM_SHA224 then CKM_SHA224
  else if ul == _CKM_SHA256 then CKM_SHA256
  else if ul == _CKM_SHA512 then CKM_SHA512
  else if ul == _CKM_MD5 then CKM_MD5
  else if ul == _CKM_RSA_PKCS_KEY_PAIR_GEN then CKM_RSA_PKCS_KEY_PAIR_GEN
  else if ul == _CKM_RSA_X9_31_KEY_PAIR_GEN then CKM_RSA_X9_31_KEY_PAIR_GEN
  else if ul == _CKM_RSA_PKCS then CKM_RSA_PKCS
  else if ul == _CKM_RSA_PKCS_OAEP then CKM_RSA_PKCS_OAEP (unsafe_get_oaep t)
  else if ul == _CKM_RSA_X_509 then CKM_RSA_X_509
  else if ul == _CKM_RSA_PKCS_PSS then CKM_RSA_PKCS_PSS (unsafe_get_pss t)
  else if ul == _CKM_SHA1_RSA_PKCS then CKM_SHA1_RSA_PKCS
  else if ul == _CKM_SHA224_RSA_PKCS then CKM_SHA224_RSA_PKCS
  else if ul == _CKM_SHA256_RSA_PKCS then CKM_SHA256_RSA_PKCS
  else if ul == _CKM_SHA384_RSA_PKCS then CKM_SHA384_RSA_PKCS
  else if ul == _CKM_SHA512_RSA_PKCS then CKM_SHA512_RSA_PKCS
  else if ul == _CKM_SHA1_RSA_PKCS_PSS then CKM_SHA1_RSA_PKCS_PSS (unsafe_get_pss t)
  else if ul == _CKM_SHA224_RSA_PKCS_PSS then CKM_SHA224_RSA_PKCS_PSS (unsafe_get_pss t)
  else if ul == _CKM_SHA256_RSA_PKCS_PSS then CKM_SHA256_RSA_PKCS_PSS (unsafe_get_pss t)
  else if ul == _CKM_SHA384_RSA_PKCS_PSS then CKM_SHA384_RSA_PKCS_PSS (unsafe_get_pss t)
  else if ul == _CKM_SHA512_RSA_PKCS_PSS then CKM_SHA512_RSA_PKCS_PSS (unsafe_get_pss t)
  else if ul == _CKM_AES_KEY_GEN then CKM_AES_KEY_GEN
  else if ul == _CKM_AES_ECB then CKM_AES_ECB
  else if ul == _CKM_AES_CBC then CKM_AES_CBC (unsafe_get_string t)
  else if ul == _CKM_AES_CBC_PAD then CKM_AES_CBC_PAD (unsafe_get_string t)
  else if ul == _CKM_AES_MAC then CKM_AES_MAC
  else if ul == _CKM_AES_MAC_GENERAL then
    CKM_AES_MAC_GENERAL (unsafe_get_ulong t)
  else if ul == _CKM_AES_ECB_ENCRYPT_DATA then
    CKM_AES_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  else if ul == _CKM_AES_CBC_ENCRYPT_DATA then
    CKM_AES_CBC_ENCRYPT_DATA (unsafe_get_aes_cbc_param t)
  else if ul == _CKM_DES_KEY_GEN then CKM_DES_KEY_GEN
  else if ul == _CKM_DES_ECB then CKM_DES_ECB
  else if ul == _CKM_DES_CBC then CKM_DES_CBC (unsafe_get_string t)
  else if ul == _CKM_DES_CBC_PAD then CKM_DES_CBC_PAD (unsafe_get_string t)
  else if ul == _CKM_DES_MAC then CKM_DES_MAC
  else if ul == _CKM_DES_MAC_GENERAL then
    CKM_DES_MAC_GENERAL (unsafe_get_ulong t)
  else if ul == _CKM_DES_ECB_ENCRYPT_DATA then
    CKM_DES_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  else if ul == _CKM_DES_CBC_ENCRYPT_DATA then
    CKM_DES_CBC_ENCRYPT_DATA (unsafe_get_des_cbc_param t)
  else if ul == _CKM_DES3_KEY_GEN then CKM_DES3_KEY_GEN
  else if ul == _CKM_DES3_ECB then CKM_DES3_ECB
  else if ul == _CKM_DES3_CBC then CKM_DES3_CBC (unsafe_get_string t)
  else if ul == _CKM_DES3_CBC_PAD then CKM_DES3_CBC_PAD (unsafe_get_string t)
  else if ul == _CKM_DES3_MAC then CKM_DES3_MAC
  else if ul == _CKM_DES3_MAC_GENERAL then
    CKM_DES3_MAC_GENERAL (unsafe_get_ulong t)
  else if ul == _CKM_DES3_ECB_ENCRYPT_DATA then
    CKM_DES3_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  else if ul == _CKM_DES3_CBC_ENCRYPT_DATA then
    CKM_DES3_CBC_ENCRYPT_DATA (unsafe_get_des_cbc_param t)
  else if ul == _CKM_CONCATENATE_BASE_AND_DATA then
    CKM_CONCATENATE_BASE_AND_DATA (unsafe_get_derivation_string t)
  else if ul == _CKM_CONCATENATE_DATA_AND_BASE then
    CKM_CONCATENATE_DATA_AND_BASE (unsafe_get_derivation_string t)
  else if ul == _CKM_XOR_BASE_AND_DATA then
    CKM_XOR_BASE_AND_DATA (unsafe_get_derivation_string t)
  else if ul == _CKM_EXTRACT_KEY_FROM_KEY then
    CKM_EXTRACT_KEY_FROM_KEY (unsafe_get_ulong t)
  else if ul == _CKM_CONCATENATE_BASE_AND_KEY then
    CKM_CONCATENATE_BASE_AND_KEY (unsafe_get_ulong t)
  else if ul == _CKM_EC_KEY_PAIR_GEN then CKM_EC_KEY_PAIR_GEN
  else if ul == _CKM_ECDSA then CKM_ECDSA
  else if ul == _CKM_ECDSA_SHA1 then CKM_ECDSA_SHA1
  else if ul == _CKM_ECDH1_DERIVE then
    CKM_ECDH1_DERIVE (unsafe_get_ecdh1_derive_param t)
  else if ul == _CKM_ECDH1_COFACTOR_DERIVE then
    CKM_ECDH1_COFACTOR_DERIVE (unsafe_get_ecdh1_derive_param t)
  else if ul == _CKM_ECMQV_DERIVE then
    CKM_ECMQV_DERIVE (unsafe_get_ecmqv_derive_param t)
  else CKM_CS_UNKNOWN (ul, (unsafe_get_string t))
