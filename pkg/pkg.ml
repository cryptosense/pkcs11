#use "topfind"
#require "topkg"
open Topkg

let api =
  [ "Pkcs11"
  ; "P11"
  ; "Pkcs11_CK_RV"
  ; "Pkcs11_CK_ULONG"
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
  ; "Pkcs11_CK_BIGINT"
  ; "Pkcs11_hex_data"
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
  ; "Pkcs11_CK_PKCS5_PBKD2_DATA_PARAMS"
  ; "Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE"
  ; "Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE"
  ; "Pkcs11_CK_RAW_PAYLOAD"
  ; "Pkcs11_CK_MECHANISM_INFO"
  ; "Pkcs11_slot_list"
  ; "Pkcs11_CK_SLOT_ID"
  ; "Pkcs11_CK_SLOT_INFO"
  ; "Pkcs11_CK_HW_FEATURE_TYPE"
  ; "Pkcs11_CK_SESSION_HANDLE"
  ; "Pkcs11_CK_VOID"
  ; "P11_mechanisms"
  ; "P11_keys_attributes"
  ]

let () =
  Pkg.describe "pkcs11" @@ fun c ->
  Ok [
    Pkg.mllib ~api "src/pkcs11.mllib";
    Pkg.clib "src/libpkcs11_stubs.clib";
    Pkg.test "test/test_suite";
    Pkg.lib "include/pkcs11.h";
    Pkg.lib "include/pkcs11t.h";
    Pkg.lib "include/pkcs11f.h";
    Pkg.lib "include/pkcs11_module.h";
  ]
