#use "topfind"
#require "topkg"
open Topkg

let api =
  [ "Pkcs11"
  ; "P11"
  ; "Pkcs11_CK_RV"
  ; "P11_ulong"
  ; "Pkcs11_log"
  ; "Pkcs11_data"
  ; "Pkcs11_CK_BYTE"
  ; "Ctypes_helpers"
  ; "Pkcs11_CK_SESSION_INFO"
  ; "Pkcs11_CK_FLAGS"
  ; "Pkcs11_CK_ATTRIBUTE_SET"
  ; "Pkcs11_CK_OBJECT_CLASS"
  ; "Pkcs11_CK_KEY_TYPE"
  ; "Pkcs11_CK_ATTRIBUTE"
  ; "P11_bigint"
  ; "P11_hex_data"
  ; "P11_driver"
  ; "Pkcs11_key_gen_mechanism"
  ; "Pkcs11_CK_MECHANISM_TYPE"
  ; "Pkcs11_CK_ATTRIBUTE_TYPE"
  ; "Pkcs11_CK_BBOOL"
  ; "Pkcs11_mechanism_list"
  ; "Pkcs11_template"
  ; "Pkcs11_CK_TOKEN_INFO"
  ; "Pkcs11_CK_VERSION"
  ; "Pkcs11_CK_UTF8CHAR"
  ; "Pkcs11_CK_INFO"
  ; "Pkcs11_CK_USER_TYPE"
  ; "Pkcs11_CK_MECHANISM"
  ; "Pkcs11_CK_ECMQV_DERIVE_PARAMS"
  ; "Pkcs11_CK_EC_KDF_TYPE"
  ; "Pkcs11_CK_OBJECT_HANDLE"
  ; "Pkcs11_CK_ECDH1_DERIVE_PARAMS"
  ; "Pkcs11_CK_KEY_DERIVATION_STRING_DATA"
  ; "Pkcs11_CK_RSA_PKCS_PSS_PARAMS"
  ; "Pkcs11_CK_RSA_PKCS_MGF_TYPE"
  ; "Pkcs11_CK_RSA_PKCS_OAEP_PARAMS"
  ; "Pkcs11_CK_PKCS5_PBKD2_PARAMS"
  ; "Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE"
  ; "Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE"
  ; "Pkcs11_CK_MECHANISM_INFO"
  ; "Pkcs11_slot_list"
  ; "Pkcs11_CK_SLOT_ID"
  ; "Pkcs11_CK_SLOT_INFO"
  ; "Pkcs11_CK_HW_FEATURE_TYPE"
  ; "Pkcs11_CK_SESSION_HANDLE"
  ; "Pkcs11_CK_VOID"
  ; "P11_key_attributes"
  ; "P11_template"
  ; "P11_attribute"
  ; "P11_attribute_types"
  ; "P11_attribute_type"
  ; "P11_ecdh1_derive_params"
  ; "P11_ecmqv_derive_params"
  ; "P11_session_info"
  ; "P11_mechanism_info"
  ; "P11_slot_info"
  ; "P11_token_info"
  ; "P11_info"
  ; "P11_user_type"
  ; "P11_mechanism"
  ; "P11_pkcs5_pbkd2_data_params"
  ; "P11_pkcs5_pbkd2_pseudo_random_function_type"
  ; "P11_pkcs5_pbkdf2_salt_source_type"
  ; "P11_des_cbc_encrypt_data_params"
  ; "P11_aes_cbc_encrypt_data_params"
  ; "P11_rsa_pkcs_pss_params"
  ; "P11_rsa_pkcs_oaep_params"
  ; "P11_rsa_pkcs_mgf_type"
  ; "P11_key_gen_mechanism"
  ; "P11_mechanism_type"
  ; "P11_rv"
  ; "P11_version"
  ; "P11_key_type"
  ; "P11_object_class"
  ; "P11_flags"
  ; "P11_slot_id"
  ; "P11_slot"
  ; "P11_hw_feature_type"
  ; "P11_object_handle"
  ; "P11_session_handle"
  ; "P11_ec_kdf"
  ]

let cmdliner = Conf.with_pkg "cmdliner"

let () =
  Pkg.describe "pkcs11" @@ fun c ->
  let cmdliner = Conf.value c cmdliner in
  Ok [
    Pkg.mllib ~api "src/pkcs11.mllib";
    Pkg.clib "src/libpkcs11_stubs.clib";
    Pkg.test "test/test_suite";
    Pkg.lib "include/pkcs11.h";
    Pkg.lib "include/pkcs11t.h";
    Pkg.lib "include/pkcs11f.h";
    Pkg.lib "include/pkcs11_module.h";
    Pkg.mllib ~api:["Pkcs11_rev"] "src_rev/pkcs11_rev.mllib";
    Pkg.clib "src_rev/libpkcs11_rev_stubs.clib";
    Pkg.clib "src_rev/libpkcs11_rev_dllmain.clib";
    Pkg.mllib ~cond:cmdliner "src_cli/pkcs11_cli.mllib";
    Pkg.test ~run:false "test/example_sign";
    Pkg.clib "src_dll/libpkcs11_fake.clib";
  ]
