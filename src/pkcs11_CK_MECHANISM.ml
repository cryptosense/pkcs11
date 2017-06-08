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

let make =
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
  let open P11_mechanism in
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
    | CKM_CS_UNKNOWN params ->
      simple params

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

let view t =
  let open P11_mechanism in
  let open Pkcs11_CK_MECHANISM_TYPE in
  let ul = getf t mechanism in
  let l = view ul in
  let it_is c =
    P11_mechanism_type.equal l @@ view c
  in
  match () with
  | _ when it_is _CKM_SHA_1 -> CKM_SHA_1
  | _ when it_is _CKM_SHA224 -> CKM_SHA224
  | _ when it_is _CKM_SHA256 -> CKM_SHA256
  | _ when it_is _CKM_SHA512 -> CKM_SHA512
  | _ when it_is _CKM_MD5 -> CKM_MD5
  | _ when it_is _CKM_RSA_PKCS_KEY_PAIR_GEN -> CKM_RSA_PKCS_KEY_PAIR_GEN
  | _ when it_is _CKM_RSA_X9_31_KEY_PAIR_GEN -> CKM_RSA_X9_31_KEY_PAIR_GEN
  | _ when it_is _CKM_RSA_PKCS -> CKM_RSA_PKCS
  | _ when it_is _CKM_RSA_PKCS_OAEP -> CKM_RSA_PKCS_OAEP (unsafe_get_oaep t)
  | _ when it_is _CKM_RSA_X_509 -> CKM_RSA_X_509
  | _ when it_is _CKM_RSA_PKCS_PSS -> CKM_RSA_PKCS_PSS (unsafe_get_pss t)
  | _ when it_is _CKM_SHA1_RSA_PKCS -> CKM_SHA1_RSA_PKCS
  | _ when it_is _CKM_SHA224_RSA_PKCS -> CKM_SHA224_RSA_PKCS
  | _ when it_is _CKM_SHA256_RSA_PKCS -> CKM_SHA256_RSA_PKCS
  | _ when it_is _CKM_SHA384_RSA_PKCS -> CKM_SHA384_RSA_PKCS
  | _ when it_is _CKM_SHA512_RSA_PKCS -> CKM_SHA512_RSA_PKCS
  | _ when it_is _CKM_SHA1_RSA_PKCS_PSS -> CKM_SHA1_RSA_PKCS_PSS (unsafe_get_pss t)
  | _ when it_is _CKM_SHA224_RSA_PKCS_PSS -> CKM_SHA224_RSA_PKCS_PSS (unsafe_get_pss t)
  | _ when it_is _CKM_SHA256_RSA_PKCS_PSS -> CKM_SHA256_RSA_PKCS_PSS (unsafe_get_pss t)
  | _ when it_is _CKM_SHA384_RSA_PKCS_PSS -> CKM_SHA384_RSA_PKCS_PSS (unsafe_get_pss t)
  | _ when it_is _CKM_SHA512_RSA_PKCS_PSS -> CKM_SHA512_RSA_PKCS_PSS (unsafe_get_pss t)
  | _ when it_is _CKM_AES_KEY_GEN -> CKM_AES_KEY_GEN
  | _ when it_is _CKM_AES_ECB -> CKM_AES_ECB
  | _ when it_is _CKM_AES_CBC -> CKM_AES_CBC (unsafe_get_string t)
  | _ when it_is _CKM_AES_CBC_PAD -> CKM_AES_CBC_PAD (unsafe_get_string t)
  | _ when it_is _CKM_AES_MAC -> CKM_AES_MAC
  | _ when it_is _CKM_AES_MAC_GENERAL -> CKM_AES_MAC_GENERAL (unsafe_get_ulong t)
  | _ when it_is _CKM_AES_ECB_ENCRYPT_DATA -> CKM_AES_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  | _ when it_is _CKM_AES_CBC_ENCRYPT_DATA -> CKM_AES_CBC_ENCRYPT_DATA (unsafe_get_aes_cbc_param t)
  | _ when it_is _CKM_DES_KEY_GEN -> CKM_DES_KEY_GEN
  | _ when it_is _CKM_DES_ECB -> CKM_DES_ECB
  | _ when it_is _CKM_DES_CBC -> CKM_DES_CBC (unsafe_get_string t)
  | _ when it_is _CKM_DES_CBC_PAD -> CKM_DES_CBC_PAD (unsafe_get_string t)
  | _ when it_is _CKM_DES_MAC -> CKM_DES_MAC
  | _ when it_is _CKM_DES_MAC_GENERAL -> CKM_DES_MAC_GENERAL (unsafe_get_ulong t)
  | _ when it_is _CKM_DES_ECB_ENCRYPT_DATA -> CKM_DES_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  | _ when it_is _CKM_DES_CBC_ENCRYPT_DATA -> CKM_DES_CBC_ENCRYPT_DATA (unsafe_get_des_cbc_param t)
  | _ when it_is _CKM_DES3_KEY_GEN -> CKM_DES3_KEY_GEN
  | _ when it_is _CKM_DES3_ECB -> CKM_DES3_ECB
  | _ when it_is _CKM_DES3_CBC -> CKM_DES3_CBC (unsafe_get_string t)
  | _ when it_is _CKM_DES3_CBC_PAD -> CKM_DES3_CBC_PAD (unsafe_get_string t)
  | _ when it_is _CKM_DES3_MAC -> CKM_DES3_MAC
  | _ when it_is _CKM_DES3_MAC_GENERAL -> CKM_DES3_MAC_GENERAL (unsafe_get_ulong t)
  | _ when it_is _CKM_DES3_ECB_ENCRYPT_DATA -> CKM_DES3_ECB_ENCRYPT_DATA (unsafe_get_derivation_string t)
  | _ when it_is _CKM_DES3_CBC_ENCRYPT_DATA -> CKM_DES3_CBC_ENCRYPT_DATA (unsafe_get_des_cbc_param t)
  | _ when it_is _CKM_CONCATENATE_BASE_AND_DATA -> CKM_CONCATENATE_BASE_AND_DATA (unsafe_get_derivation_string t)
  | _ when it_is _CKM_CONCATENATE_DATA_AND_BASE -> CKM_CONCATENATE_DATA_AND_BASE (unsafe_get_derivation_string t)
  | _ when it_is _CKM_XOR_BASE_AND_DATA -> CKM_XOR_BASE_AND_DATA (unsafe_get_derivation_string t)
  | _ when it_is _CKM_EXTRACT_KEY_FROM_KEY -> CKM_EXTRACT_KEY_FROM_KEY (unsafe_get_ulong t)
  | _ when it_is _CKM_CONCATENATE_BASE_AND_KEY -> CKM_CONCATENATE_BASE_AND_KEY (unsafe_get_ulong t)
  | _ when it_is _CKM_EC_KEY_PAIR_GEN -> CKM_EC_KEY_PAIR_GEN
  | _ when it_is _CKM_ECDSA -> CKM_ECDSA
  | _ when it_is _CKM_ECDSA_SHA1 -> CKM_ECDSA_SHA1
  | _ when it_is _CKM_ECDH1_DERIVE -> CKM_ECDH1_DERIVE (unsafe_get_ecdh1_derive_param t)
  | _ when it_is _CKM_ECDH1_COFACTOR_DERIVE -> CKM_ECDH1_COFACTOR_DERIVE (unsafe_get_ecdh1_derive_param t)
  | _ when it_is _CKM_ECMQV_DERIVE -> CKM_ECMQV_DERIVE (unsafe_get_ecmqv_derive_param t)
  | _ ->
    CKM_CS_UNKNOWN ul
