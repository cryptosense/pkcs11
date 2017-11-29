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

let argument =
  let open P11_mechanism in
  function
  | CKM_SHA_1 -> No_argument
  | CKM_SHA224 -> No_argument
  | CKM_SHA256 -> No_argument
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
  | CKM_ECDH1_DERIVE p -> ECDH1 p
  | CKM_ECDH1_COFACTOR_DERIVE p -> ECDH1 p
  | CKM_ECMQV_DERIVE p -> ECMQV p
  | CKM_PKCS5_PBKD2 p -> PBKD2 p
  | CKM_DSA_SHA1 -> No_argument
  | CKM_DSA_SHA224 -> No_argument
  | CKM_DSA_SHA256 -> No_argument
  | CKM_DSA_SHA384 -> No_argument
  | CKM_DSA_SHA512 -> No_argument
  | CKM_CS_UNKNOWN params -> No_argument

let argument_params argument =
  let struct_ params ctype make_ctype =
    let params = make_ctype params in
    let param = to_voidp (addr params) in
    let param_len = Unsigned.ULong.of_int (sizeof ctype) in
    (param, param_len)
  in
  match argument with
  | No_argument ->
    (null, Unsigned.ULong.zero)
  | OAEP p ->
    struct_ p Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.t Pkcs11_CK_RSA_PKCS_OAEP_PARAMS.make
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
    struct_ p Pkcs11_CK_KEY_DERIVATION_STRING_DATA.t Pkcs11_CK_KEY_DERIVATION_STRING_DATA.make
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

let make x =
  let ckm = Pkcs11_CK_MECHANISM_TYPE.make @@ P11_mechanism.mechanism_type x in
  let (param, param_len) = argument_params @@ argument x in
  let m = make ck_mechanism in
  setf m mechanism ckm;
  Reachable_ptr.setf m parameter param;
  setf m parameter_len param_len;
  m

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
  | _ when it_is _CKM_DSA_SHA1 -> CKM_DSA_SHA1
  | _ when it_is _CKM_DSA_SHA224 -> CKM_DSA_SHA224
  | _ when it_is _CKM_DSA_SHA256 -> CKM_DSA_SHA256
  | _ when it_is _CKM_DSA_SHA384 -> CKM_DSA_SHA384
  | _ when it_is _CKM_DSA_SHA512 -> CKM_DSA_SHA512
  | _ ->
    CKM_CS_UNKNOWN ul
