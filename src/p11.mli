(** High-level PKCS#11 interface. *)

module Data :
sig
  type t = string [@@deriving yojson]

  (** Remove unnecessary leading ['\000']. *)
  val normalize: t -> t

  val compare : t -> t -> int
end

module Session_handle = P11_session_handle
module Object_handle = P11_object_handle
module HW_feature_type = P11_hw_feature_type
module Slot = P11_slot
module Slot_id = P11_slot_id

module Flags :
sig
  type t = Pkcs11.CK_FLAGS.t
  [@@deriving yojson]
  val empty : t
  val compare : t -> t -> int
  val equal : t -> t -> bool
  val logical_or : t -> t -> t
  val ( || ) : t -> t -> t
  val get : flags: t -> flag: t -> bool
  val _CKF_TOKEN_PRESENT : t
  val _CKF_REMOVABLE_DEVICE : t
  val _CKF_HW_SLOT : t
  val _CKF_RNG : t
  val _CKF_WRITE_PROTECTED : t
  val _CKF_LOGIN_REQUIRED : t
  val _CKF_USER_PIN_INITIALIZED : t
  val _CKF_RESTORE_KEY_NOT_NEEDED : t
  val _CKF_CLOCK_ON_TOKEN : t
  val _CKF_PROTECTED_AUTHENTICATION_PATH : t
  val _CKF_DUAL_CRYPTO_OPERATIONS : t
  val _CKF_TOKEN_INITIALIZED : t
  val _CKF_SECONDARY_AUTHENTICATION : t
  val _CKF_USER_PIN_COUNT_LOW : t
  val _CKF_USER_PIN_FINAL_TRY : t
  val _CKF_USER_PIN_LOCKED : t
  val _CKF_USER_PIN_TO_BE_CHANGED : t
  val _CKF_SO_PIN_COUNT_LOW : t
  val _CKF_SO_PIN_FINAL_TRY : t
  val _CKF_SO_PIN_LOCKED : t
  val _CKF_SO_PIN_TO_BE_CHANGED : t
  val _CKF_RW_SESSION : t
  val _CKF_SERIAL_SESSION : t
  val _CKF_ARRAY_ATTRIBUTE : t
  val _CKF_HW : t
  val _CKF_ENCRYPT : t
  val _CKF_DECRYPT : t
  val _CKF_DIGEST : t
  val _CKF_SIGN : t
  val _CKF_SIGN_RECOVER : t
  val _CKF_VERIFY : t
  val _CKF_VERIFY_RECOVER : t
  val _CKF_GENERATE : t
  val _CKF_GENERATE_KEY_PAIR : t
  val _CKF_WRAP : t
  val _CKF_UNWRAP : t
  val _CKF_DERIVE : t
  val _CKF_EC_F_P : t
  val _CKF_EC_F_2M : t
  val _CKF_EC_ECPARAMETERS : t
  val _CKF_EC_NAMEDCURVE : t
  val _CKF_EC_UNCOMPRESS : t
  val _CKF_EC_COMPRESS : t
  val _CKF_EXTENSION : t
  val _CKF_LIBRARY_CANT_CREATE_OS_THREADS : t
  val _CKF_OS_LOCKING_OK : t
  val _CKF_DONT_BLOCK : t
  val _CKF_NEXT_OTP : t
  val _CKF_EXCLUDE_TIME : t
  val _CKF_EXCLUDE_COUNTER : t
  val _CKF_EXCLUDE_CHALLENGE : t
  val _CKF_EXCLUDE_PIN : t
  val _CKF_USER_FRIENDLY_OTP : t
  val to_string : t -> string
  val of_string : string -> t
end

module Object_class :
sig
  type t = Pkcs11.CK_OBJECT_CLASS.u =
    | CKO_DATA
    | CKO_CERTIFICATE
    | CKO_PUBLIC_KEY
    | CKO_PRIVATE_KEY
    | CKO_SECRET_KEY
    | CKO_HW_FEATURE
    | CKO_DOMAIN_PARAMETERS
    | CKO_MECHANISM
    | CKO_OTP_KEY
    | CKO_VENDOR_DEFINED

    (* This is a catch-all case that makes it possible to deal with
       vendor-specific/non-standard CKO. *)
    | CKO_CS_UNKNOWN of Unsigned.ULong.t
  [@@deriving eq,ord,show,yojson]

  val of_string : string -> t
  val to_string : t -> string
end

module Key_type :
sig
  type t = Pkcs11.CK_KEY_TYPE.u =
    | CKK_RSA
    | CKK_DSA
    | CKK_DH
    | CKK_EC
    | CKK_X9_42_DH
    | CKK_KEA
    | CKK_GENERIC_SECRET
    | CKK_RC2
    | CKK_RC4
    | CKK_DES
    | CKK_DES2
    | CKK_DES3
    | CKK_CAST
    | CKK_CAST3
    | CKK_CAST128
    | CKK_RC5
    | CKK_IDEA
    | CKK_SKIPJACK
    | CKK_BATON
    | CKK_JUNIPER
    | CKK_CDMF
    | CKK_AES
    | CKK_BLOWFISH
    | CKK_TWOFISH
    | CKK_SECURID
    | CKK_HOTP
    | CKK_ACTI
    | CKK_CAMELLIA
    | CKK_ARIA
    | CKK_VENDOR_DEFINED

    (* This is a catch-all case that makes it possible to deal with
       vendor-specific/non-standard CKK. *)
    | CKK_CS_UNKNOWN of Unsigned.ULong.t
    [@@deriving yojson]

  val compare: t -> t -> int
  val equal : t -> t -> bool
  val of_string : string -> t
  val to_string : t -> string
end

module Version :
sig
  type t = Pkcs11.CK_VERSION.u =
    { major : int; minor : int; }
  [@@deriving eq,show,yojson]
  val to_string : t -> string
end

module Bigint = Pkcs11.CK_BIGINT

module RV :
sig
  type t = Pkcs11.CK_RV.u =
    | CKR_OK
    | CKR_CANCEL
    | CKR_HOST_MEMORY
    | CKR_SLOT_ID_INVALID
    | CKR_GENERAL_ERROR
    | CKR_FUNCTION_FAILED
    | CKR_ARGUMENTS_BAD
    | CKR_NO_EVENT
    | CKR_NEED_TO_CREATE_THREADS
    | CKR_CANT_LOCK
    | CKR_ATTRIBUTE_READ_ONLY
    | CKR_ATTRIBUTE_SENSITIVE
    | CKR_ATTRIBUTE_TYPE_INVALID
    | CKR_ATTRIBUTE_VALUE_INVALID
    | CKR_DATA_INVALID
    | CKR_DATA_LEN_RANGE
    | CKR_DEVICE_ERROR
    | CKR_DEVICE_MEMORY
    | CKR_DEVICE_REMOVED
    | CKR_ENCRYPTED_DATA_INVALID
    | CKR_ENCRYPTED_DATA_LEN_RANGE
    | CKR_FUNCTION_CANCELED
    | CKR_FUNCTION_NOT_PARALLEL
    | CKR_FUNCTION_NOT_SUPPORTED
    | CKR_KEY_HANDLE_INVALID
    | CKR_KEY_SIZE_RANGE
    | CKR_KEY_TYPE_INCONSISTENT
    | CKR_KEY_NOT_NEEDED
    | CKR_KEY_CHANGED
    | CKR_KEY_NEEDED
    | CKR_KEY_INDIGESTIBLE
    | CKR_KEY_FUNCTION_NOT_PERMITTED
    | CKR_KEY_NOT_WRAPPABLE
    | CKR_KEY_UNEXTRACTABLE
    | CKR_MECHANISM_INVALID
    | CKR_MECHANISM_PARAM_INVALID
    | CKR_OBJECT_HANDLE_INVALID
    | CKR_OPERATION_ACTIVE
    | CKR_OPERATION_NOT_INITIALIZED
    | CKR_PIN_INCORRECT
    | CKR_PIN_INVALID
    | CKR_PIN_LEN_RANGE
    | CKR_PIN_EXPIRED
    | CKR_PIN_LOCKED
    | CKR_SESSION_CLOSED
    | CKR_SESSION_COUNT
    | CKR_SESSION_HANDLE_INVALID
    | CKR_SESSION_PARALLEL_NOT_SUPPORTED
    | CKR_SESSION_READ_ONLY
    | CKR_SESSION_EXISTS
    | CKR_SESSION_READ_ONLY_EXISTS
    | CKR_SESSION_READ_WRITE_SO_EXISTS
    | CKR_SIGNATURE_INVALID
    | CKR_SIGNATURE_LEN_RANGE
    | CKR_TEMPLATE_INCOMPLETE
    | CKR_TEMPLATE_INCONSISTENT
    | CKR_TOKEN_NOT_PRESENT
    | CKR_TOKEN_NOT_RECOGNIZED
    | CKR_TOKEN_WRITE_PROTECTED
    | CKR_UNWRAPPING_KEY_HANDLE_INVALID
    | CKR_UNWRAPPING_KEY_SIZE_RANGE
    | CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
    | CKR_USER_ALREADY_LOGGED_IN
    | CKR_USER_NOT_LOGGED_IN
    | CKR_USER_PIN_NOT_INITIALIZED
    | CKR_USER_TYPE_INVALID
    | CKR_USER_ANOTHER_ALREADY_LOGGED_IN
    | CKR_USER_TOO_MANY_TYPES
    | CKR_WRAPPED_KEY_INVALID
    | CKR_WRAPPED_KEY_LEN_RANGE
    | CKR_WRAPPING_KEY_HANDLE_INVALID
    | CKR_WRAPPING_KEY_SIZE_RANGE
    | CKR_WRAPPING_KEY_TYPE_INCONSISTENT
    | CKR_RANDOM_SEED_NOT_SUPPORTED
    | CKR_RANDOM_NO_RNG
    | CKR_DOMAIN_PARAMS_INVALID
    | CKR_BUFFER_TOO_SMALL
    | CKR_SAVED_STATE_INVALID
    | CKR_INFORMATION_SENSITIVE
    | CKR_STATE_UNSAVEABLE
    | CKR_CRYPTOKI_NOT_INITIALIZED
    | CKR_CRYPTOKI_ALREADY_INITIALIZED
    | CKR_MUTEX_BAD
    | CKR_MUTEX_NOT_LOCKED
    | CKR_NEW_PIN_MODE
    | CKR_NEXT_OTP
    | CKR_FUNCTION_REJECTED
    | CKR_VENDOR_DEFINED
    | CKR_CS_UNKNOWN of Unsigned.ULong.t

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val to_string : t -> string
  val of_string : string -> t
end

module Mechanism_type :
sig
  type t = Pkcs11.CK_MECHANISM_TYPE.u =
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
    | CKM_VENDOR_DEFINED
    | CKM_CS_UNKNOWN of Pkcs11.CK_MECHANISM_TYPE.t
    [@@deriving yojson]

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val to_string : t -> string

  (** The list of all the CKM codes defined above, minus the vendor defined one. *)
  val elements : t list
end

module Key_gen_mechanism : sig
  type t = Pkcs11.Key_gen_mechanism.u =
    | CKM of Mechanism_type.t
    | CK_UNAVAILABLE_INFORMATION  [@@deriving yojson]
end

module RSA_PKCS_MGF_type :
sig
  type t = Pkcs11.CK_RSA_PKCS_MGF_TYPE.t
  val _CKG_MGF1_SHA1 : t
  val _CKG_MGF1_SHA256 : t
  val _CKG_MGF1_SHA384 : t
  val _CKG_MGF1_SHA512 : t
  val _CKG_MGF1_SHA224 : t
end

module RSA_PKCS_OAEP_params :
sig
  type t = Pkcs11.CK_RSA_PKCS_OAEP_PARAMS.u =
    {
      hashAlg: Mechanism_type.t;
      mgf: RSA_PKCS_MGF_type.t;
      src: string option;
    }
end

module RSA_PKCS_PSS_params :
sig
  type t = Pkcs11.CK_RSA_PKCS_PSS_PARAMS.u =
    {
      hashAlg: Mechanism_type.t;
      mgf: RSA_PKCS_MGF_type.t;
      sLen: Pkcs11_CK_ULONG.t;
    }
end

module AES_CBC_ENCRYPT_DATA_params :
sig
  type t = Pkcs11.CK_AES_CBC_ENCRYPT_DATA_PARAMS.u =
    {
      iv: string;
      data: string;
    }
end

module DES_CBC_ENCRYPT_DATA_params :
sig
  type t = Pkcs11.CK_DES_CBC_ENCRYPT_DATA_PARAMS.u =
    {
      iv: string;
      data: string;
    }
end

module PKCS5_PBKDF2_SALT_SOURCE_type :
sig
  type t = Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.u
end

module PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_type :
sig
  type t = Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.u
end

module PKCS5_PBKD2_DATA_params :
sig
  type t = Pkcs11.CK_PKCS5_PBKD2_PARAMS.u =
    {
      saltSource: PKCS5_PBKDF2_SALT_SOURCE_type.t;
      saltSourceData: string option;
      iterations: int;
      prf: PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_type.t;
      prfData: string option;
      password: string;
    }
end

module RAW_PAYLOAD_params :
sig
  type t = Pkcs11.CK_RAW_PAYLOAD.t
end

module Mechanism :
sig
  type t = Pkcs11.CK_MECHANISM.u =
    | CKM_SHA_1
    | CKM_SHA224
    | CKM_SHA256
    | CKM_SHA512
    | CKM_MD5
    | CKM_RSA_PKCS_KEY_PAIR_GEN
    | CKM_RSA_X9_31_KEY_PAIR_GEN
    | CKM_RSA_PKCS
    | CKM_RSA_PKCS_OAEP of RSA_PKCS_OAEP_params.t
    | CKM_RSA_X_509
    | CKM_RSA_PKCS_PSS of RSA_PKCS_PSS_params.t
    | CKM_SHA1_RSA_PKCS
    | CKM_SHA224_RSA_PKCS
    | CKM_SHA256_RSA_PKCS
    | CKM_SHA384_RSA_PKCS
    | CKM_SHA512_RSA_PKCS
    | CKM_SHA1_RSA_PKCS_PSS of RSA_PKCS_PSS_params.t
    | CKM_SHA224_RSA_PKCS_PSS of RSA_PKCS_PSS_params.t
    | CKM_SHA256_RSA_PKCS_PSS of RSA_PKCS_PSS_params.t
    | CKM_SHA384_RSA_PKCS_PSS of RSA_PKCS_PSS_params.t
    | CKM_SHA512_RSA_PKCS_PSS of RSA_PKCS_PSS_params.t
    | CKM_AES_KEY_GEN
    | CKM_AES_ECB
    | CKM_AES_CBC of Data.t
    | CKM_AES_CBC_PAD of Data.t
    | CKM_AES_MAC
    | CKM_AES_MAC_GENERAL of Pkcs11_CK_ULONG.t
    | CKM_AES_ECB_ENCRYPT_DATA of Data.t
    | CKM_AES_CBC_ENCRYPT_DATA of AES_CBC_ENCRYPT_DATA_params.t
    | CKM_DES_KEY_GEN
    | CKM_DES_ECB
    | CKM_DES_CBC of Data.t
    | CKM_DES_CBC_PAD of Data.t
    | CKM_DES_MAC
    | CKM_DES_MAC_GENERAL of Pkcs11_CK_ULONG.t
    | CKM_DES_ECB_ENCRYPT_DATA of Data.t
    | CKM_DES_CBC_ENCRYPT_DATA of DES_CBC_ENCRYPT_DATA_params.t
    | CKM_DES3_KEY_GEN
    | CKM_DES3_ECB
    | CKM_DES3_CBC of Data.t
    | CKM_DES3_CBC_PAD of Data.t
    | CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL of Pkcs11_CK_ULONG.t
    | CKM_DES3_ECB_ENCRYPT_DATA of Data.t
    | CKM_DES3_CBC_ENCRYPT_DATA of DES_CBC_ENCRYPT_DATA_params.t
    | CKM_CONCATENATE_BASE_AND_DATA of Data.t
    | CKM_CONCATENATE_DATA_AND_BASE of Data.t
    | CKM_XOR_BASE_AND_DATA of Data.t
    | CKM_EXTRACT_KEY_FROM_KEY of Pkcs11_CK_ULONG.t
    | CKM_CONCATENATE_BASE_AND_KEY of Object_handle.t
    | CKM_EC_KEY_PAIR_GEN
    | CKM_ECDSA
    | CKM_ECDSA_SHA1
    | CKM_ECDH1_DERIVE of Pkcs11.CK_ECDH1_DERIVE_PARAMS.u
    | CKM_ECDH1_COFACTOR_DERIVE of Pkcs11.CK_ECDH1_DERIVE_PARAMS.u
    | CKM_ECMQV_DERIVE of Pkcs11.CK_ECMQV_DERIVE_PARAMS.u
    | CKM_PKCS5_PBKD2 of PKCS5_PBKD2_DATA_params.t
    | CKM_CS_UNKNOWN of RAW_PAYLOAD_params.t
    [@@deriving yojson]

  val mechanism_type: t -> Mechanism_type.t
  val compare: t -> t -> int

  (** [to_string] is defined as [fun x -> Mechanism_type.to_string (mechanism_type x) ]  *)
  val to_string : t -> string

  val pp : Format.formatter -> t -> unit

  val of_raw : Pkcs11.CK_MECHANISM.t -> t

  (** Kinds are "tags" on mechanisms which describe how they can be
      used. *)
  type kind =
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



    (** [kinds mechanism] returns the tags for the mechanism
      [mechanism].  *)
  val kinds : t -> kind list

  (** [is kinds t] checks that the mechanism [t] has all the tags in
      the list [kinds].  *)
  val is: kind list -> t -> bool

  (** [key_type t] returns the type of keys associated to the mechanism [t]. *)
  val key_type: t -> Key_type.t option
end

module User_type :
sig
  type t = Pkcs11.CK_USER_TYPE.u =
    | CKU_SO
    | CKU_USER
    | CKU_CONTEXT_SPECIFIC
    | CKU_CS_UNKNOWN of Unsigned.ULong.t
    [@@deriving yojson]

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val to_string : t -> string
  val of_string : string -> t
end

module Info :
sig
  type t = Pkcs11.CK_INFO.u =
    {
      cryptokiVersion : Version.t;
      manufacturerID : string;
      flags : Flags.t;
      libraryDescription : string;
      libraryVersion : Version.t;
    }
    [@@deriving eq,show,yojson]

  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings:  t -> string list
  val flags_to_string : Flags.t -> string
end

module Token_info :
sig
  type t = Pkcs11.CK_TOKEN_INFO.u =
    {
      label : string;
      manufacturerID : string;
      model : string;
      serialNumber : string;
      flags : Flags.t;
      ulMaxSessionCount : Unsigned.ULong.t;
      ulSessionCount : Unsigned.ULong.t;
      ulMaxRwSessionCount : Unsigned.ULong.t;
      ulRwSessionCount : Unsigned.ULong.t;
      ulMaxPinLen : Unsigned.ULong.t;
      ulMinPinLen : Unsigned.ULong.t;
      ulTotalPublicMemory : Unsigned.ULong.t;
      ulFreePublicMemory : Unsigned.ULong.t;
      ulTotalPrivateMemory : Unsigned.ULong.t;
      ulFreePrivateMemory : Unsigned.ULong.t;
      hardwareVersion : Version.t;
      firmwareVersion : Version.t;
      utcTime : string;
    }
  [@@deriving yojson]
  val ul_to_string : Unsigned.ULong.t -> string
  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings : t -> string list
  val flags_to_string : Flags.t -> string
end

module Slot_info :
sig
  type t = Pkcs11.CK_SLOT_INFO.u =
    {
      slotDescription : string;
      manufacturerID : string;
      flags : Flags.t;
      hardwareVersion : Version.t;
      firmwareVersion : Version.t;
    }
    [@@deriving yojson]
  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings: t -> string list
  val flags_to_string : Flags.t -> string
end

module Mechanism_info :
sig
  type t = Pkcs11.CK_MECHANISM_INFO.u =
    {
      ulMinKeySize : Unsigned.ULong.t;
      ulMaxKeySize : Unsigned.ULong.t;
      flags : Flags.t;
    }
    [@@deriving yojson]

  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings :  t -> string list
  val flags_to_string : Flags.t -> string
  val flags_to_strings : Flags.t -> string list

  (* flags possible to set for mechanism infos, aggregated *)
  val allowed_flags : Flags.t
end

module Session_info :
sig
  type t = Pkcs11.CK_SESSION_INFO.u =
    {
      slotID : Unsigned.ULong.t;
      state : Unsigned.ULong.t;
      flags : Flags.t;
      ulDeviceError : Unsigned.ULong.t;
    }
  [@@deriving yojson]
  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings : t -> string list
end

module Attribute_type :
sig
  type not_implemented = Pkcs11.CK_ATTRIBUTE_TYPE.not_implemented = NOT_IMPLEMENTED of string

  type 'a t = 'a Pkcs11.CK_ATTRIBUTE_TYPE.u =
    | CKA_CLASS : Pkcs11.CK_OBJECT_CLASS.u t
    | CKA_TOKEN : bool t
    | CKA_PRIVATE : bool t
    | CKA_LABEL : string t
    | CKA_VALUE : string t
    | CKA_TRUSTED : bool t
    | CKA_CHECK_VALUE : not_implemented t
    | CKA_KEY_TYPE : Pkcs11.CK_KEY_TYPE.u t
    | CKA_SUBJECT : string t
    | CKA_ID : string t
    | CKA_SENSITIVE : bool t
    | CKA_ENCRYPT : bool t
    | CKA_DECRYPT : bool t
    | CKA_WRAP : bool t
    | CKA_UNWRAP : bool t
    | CKA_SIGN : bool t
    | CKA_SIGN_RECOVER : bool t
    | CKA_VERIFY : bool t
    | CKA_VERIFY_RECOVER : bool t
    | CKA_DERIVE : bool t
    | CKA_START_DATE : not_implemented t
    | CKA_END_DATE : not_implemented t
    | CKA_MODULUS : Pkcs11.CK_BIGINT.t t
    | CKA_MODULUS_BITS : Pkcs11.CK_ULONG.t t
    | CKA_PUBLIC_EXPONENT : Pkcs11.CK_BIGINT.t t
    | CKA_PRIVATE_EXPONENT : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME_1 : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME_2 : Pkcs11.CK_BIGINT.t t
    | CKA_EXPONENT_1 : Pkcs11.CK_BIGINT.t t
    | CKA_EXPONENT_2 : Pkcs11.CK_BIGINT.t t
    | CKA_COEFFICIENT : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME : Pkcs11.CK_BIGINT.t t
    | CKA_SUBPRIME : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME_BITS : Pkcs11.CK_ULONG.t t
    | CKA_SUBPRIME_BITS : Pkcs11.CK_ULONG.t t
    | CKA_VALUE_LEN : Pkcs11.CK_ULONG.t t
    | CKA_EXTRACTABLE : bool t
    | CKA_LOCAL : bool t
    | CKA_NEVER_EXTRACTABLE : bool t
    | CKA_ALWAYS_SENSITIVE : bool t
    | CKA_KEY_GEN_MECHANISM : Key_gen_mechanism.t t
    | CKA_MODIFIABLE : bool t
    (* | CKA_ECDSA_PARAMS : string t *)
    | CKA_EC_PARAMS : Key_parsers.Asn1.EC.Params.t t
    | CKA_EC_POINT : Key_parsers.Asn1.EC.point t
    | CKA_ALWAYS_AUTHENTICATE : bool t
    | CKA_WRAP_WITH_TRUSTED : bool t
    | CKA_WRAP_TEMPLATE : not_implemented t
    | CKA_UNWRAP_TEMPLATE : not_implemented t
    | CKA_ALLOWED_MECHANISMS : not_implemented t
    | CKA_CS_UNKNOWN: Unsigned.ULong.t -> not_implemented t

  type pack = Pkcs11.CK_ATTRIBUTE_TYPE.pack = Pack : 'a t -> pack
    [@@deriving yojson]

  val of_string : string -> pack


  val compare: 'a t -> 'b t -> int
  val compare_pack: pack -> pack -> int
  val equal : 'a t -> 'b t -> bool
  val equal_pack: pack -> pack -> bool

  val to_string : 'a t -> string

  val pack_to_json : pack -> Yojson.Safe.json

  val elements: pack list
  val known_attribute_types : string list
end

module Attribute_types :
sig
  type t = Attribute_type.pack list [@@deriving yojson]

  (** Return true if an attribute_type is present in an attribute_type list. *)
  val mem : t -> 'a Attribute_type.t -> bool

  (** Remove the duplicates from a list of attribute types *)
  val remove_duplicates : t -> t

  val compare : t -> t -> int
end


module Attribute :
sig

  type 'a t = 'a Attribute_type.t * 'a
  type pack =
    Pkcs11.CK_ATTRIBUTE.pack = Pack : 'a t -> pack
  [@@deriving eq,ord,show,yojson]

  val to_string : 'a t -> string
  val to_string_pair : 'a t -> string * string

  val to_json : 'a t -> Yojson.Safe.json

  val compare_types: 'a t -> 'b t -> int
  val compare_types_pack: pack -> pack -> int
  val compare: 'a t -> 'b t -> int
  val equal: 'a t -> 'b t -> bool
  val equal_types_pack: pack -> pack -> bool
  val equal_values: 'a Attribute_type.t -> 'a -> 'a -> bool

  type kind =
    | Secret (* Can be used by secret keys. *)
    | Public (* Can be used by public keys. *)
    | Private (* Can be used by private keys. *)
    | RSA (* Can ONLY be used by RSA keys. *)
    | EC (* Can ONLY be used by elliptic curves keys. *)

  (** [kinds] returns a list of list.
     An attribute has kinds [ A; B; C ] if one of the lists returned by [kinds]
     has at least kinds [ A; B; C ]. *)
  val kinds: pack -> kind list list

  (** Return whether [a] has all kinds [k]. *)
  val is : kind list -> pack -> bool

  val equal_kind : kind -> kind -> bool
end

module Template :
sig
  type t = Attribute.pack list
    [@@deriving yojson]

  val to_string : t -> string
  val pp : Format.formatter -> t -> unit

  (** Return the value of the first occurrence of an attribute. *)
  val get : t -> 'a Attribute_type.t -> 'a option
  val get_pack : t -> Attribute_type.pack -> Attribute.pack option

  val mem : Attribute.pack -> t -> bool

  val of_raw : Pkcs11.Template.t -> t

  val normalize: t -> t

  (** Compares two normalized templates.  *)
  val compare : t -> t -> int

  val attribute_types: t -> Attribute_type.pack list

  (** [set_attribute attribute template] replaces the value of
      [attribute] in [template] if it already exists and adds
      [attribute] otherwise. *)
  val set_attribute : Attribute.pack -> t -> t

  (** [remove_attribute attribute template] removes the value
      [attribute] from [template] if present. If the attribute_type of
      [attribute] is present with a different value, does nothing. *)
  val remove_attribute: Attribute.pack -> t -> t

  (** [remove_attribute attribute_type template] removes the attribute
      type [attribute_type] from [template] if present with any
      value. *)
  val remove_attribute_type: Attribute_type.pack -> t -> t

  (** Iterate one of the above operation. Same as List.fold_right*)
  val fold: ('a -> t -> t) -> 'a list -> t -> t

  (** [union template1 template2] concatenates the templates. If an
      attribute is present in both [template1] and [template2], the
      value in [template1] is kept. *)
  val union : t -> t -> t

  (** [only_attribute_types attr_types template] keeps only the
      attributes in [template] that are present in [attr_types]. *)
  val only_attribute_types : Attribute_type.pack list -> t -> t

  (** [except_attribute_types attr_types template] removes all the
      attributes in [template] that are present in [attr_types]. *)
  val except_attribute_types : Attribute_type.pack list -> t -> t

  (** [find_attribute_types l template] look up for the value of each
      attribute type in the list l in [template]. Return [None] if one
      or several attribute types cannot be found in [template]. *)
  val find_attribute_types : Attribute_type.pack list -> t -> t option

  (** [correspond source tested] check if [tested] match
      [source].
      It means that it will return true if All the elements
      in [source] are present in [tested].
  *)
  val correspond : source:t -> tested:t -> bool

  (** [diff source tested] search for all the elements of [source]
      that are not equal to an element of [tested].

      It returns a tuple with the list of elements from source
      which are expected but not found in tested and a list of elements
      which are found but with a different value.
  *)
  val diff : source:t -> tested:t -> Attribute.pack list * Attribute.pack list

  (** [hash template] creates a digest from a template.

      It sorts the elements of the template to be sure to have the
      same digest for two templates that have attributes in different
      orders. *)
  val hash : t -> Digest.t

  (** {2 Accessors }  *)

  val get_class : t -> Pkcs11.CK_OBJECT_CLASS.u option
  val get_key_type : t -> Pkcs11.CK_KEY_TYPE.u option
  val get_label : t -> string option
end

exception CKR of RV.t

module type S =
sig
  val initialize : unit -> unit
  val finalize : unit -> unit
  val get_info : unit -> Info.t
  val get_slot: Slot.t -> (Slot_id.t, string) result
  val get_slot_list : bool -> Slot_id.t list
  val get_slot_info : slot: Slot_id.t -> Slot_info.t
  val get_token_info : slot: Slot_id.t -> Token_info.t
  val get_mechanism_list : slot: Slot_id.t -> Mechanism_type.t list
  val get_mechanism_info :
    slot: Slot_id.t -> Mechanism_type.t -> Mechanism_info.t
  val init_token : slot: Slot_id.t -> pin: string -> label: string -> unit
  val init_PIN : Session_handle.t -> pin: string -> unit
  val set_PIN : Session_handle.t -> oldpin: string -> newpin: string -> unit
  val open_session : slot: Slot_id.t -> flags: Flags.t -> Session_handle.t
  val close_session : Session_handle.t -> unit
  val close_all_sessions : slot: Slot_id.t -> unit
  val get_session_info : Session_handle.t -> Session_info.t
  val login : Session_handle.t -> User_type.t -> string -> unit
  val logout : Session_handle.t -> unit
  val create_object : Session_handle.t -> Template.t -> Object_handle.t
  val copy_object :
    Session_handle.t -> Object_handle.t -> Template.t -> Object_handle.t
  val destroy_object : Session_handle.t -> Object_handle.t -> unit

  (** May request several attributes at the same time. *)
  val get_attribute_value :
    Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t

  (** Will request attributes one by one. *)
  val get_attribute_value' :
    Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t

  (** Will request several attributes at the same time. (optimized version) *)
  (* https://blogs.janestreet.com/making-staging-explicit/ *)
  val get_attribute_value_optimized :
    Attribute_types.t ->
    [`Optimized of Session_handle.t -> Object_handle.t -> Template.t]

  val set_attribute_value :
    Session_handle.t -> Object_handle.t -> Template.t -> unit
  val find_objects :
    ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list
  val encrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val multipart_encrypt_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_encrypt_chunck :
    Session_handle.t -> Data.t -> Data.t
  val multipart_encrypt_final :
    Session_handle.t -> Data.t
  val multipart_encrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val decrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val multipart_decrypt_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_decrypt_chunck :
    Session_handle.t -> Data.t -> Data.t
  val multipart_decrypt_final :
    Session_handle.t -> Data.t
  val multipart_decrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val sign :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val sign_recover :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val multipart_sign_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_sign_chunck : Session_handle.t -> Data.t -> unit
  val multipart_sign_final : Session_handle.t -> Data.t
  val multipart_sign :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val verify :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> data: Data.t ->
    signature: Data.t -> unit
  val verify_recover :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> signature: Data.t ->
    Data.t
  val multipart_verify_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_verify_chunck : Session_handle.t -> Data.t -> unit
  val multipart_verify_final : Session_handle.t -> Data.t -> unit
  val multipart_verify :
    Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t -> unit

  val generate_key :
    Session_handle.t -> Mechanism.t -> Template.t -> Object_handle.t
  val generate_key_pair :
    Session_handle.t -> Mechanism.t -> Template.t -> Template.t ->
    (Object_handle.t * Object_handle.t)
  val wrap_key :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Object_handle.t ->
    Data.t
  val unwrap_key :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t ->
    Template.t -> Object_handle.t
  val derive_key :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Template.t ->
    Object_handle.t

  module Intermediate_level : Pkcs11.S
  module Low_level : Pkcs11.RAW
end

module Make (X: Pkcs11.RAW): S

(** May raise [Pkcs11.Cannot_load_module].  [on_unknown] will be called with a warning
    message when unsupported codes are encountered. *)
val load_driver:
  ?log_calls:(string * Format.formatter) ->
  ?on_unknown:(string -> unit) ->
  dll: string ->
  use_get_function_list: [ `Auto | `False | `True ] ->
  (module S)
