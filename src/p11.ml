(******************************************************************************)
(*                                    Types                                   *)
(******************************************************************************)

type ulong = Unsigned.ulong

let ulong_of_yojson = function
  | `String s -> Result.Ok (Unsigned.ULong.of_string s)
  | _ -> Result.Error "ulong_of_yojson: not a string"

let ulong_to_yojson ulong =
  `String (Unsigned.ULong.to_string ulong)

let ulong_typ name =
  Record.Type.make
    ~name
    ~to_yojson:ulong_to_yojson
    ~of_yojson:ulong_of_yojson
    ()

(**
    Build a of_json function out of a of_string function.
    The typename is used for the error message.
 *)
let of_json_string ~typename of_string json =
  let err msg =
    Result.Error
      (Printf.sprintf "(while parsing %s): %s" typename msg)
  in
  match json with
    | `String s ->
        begin
          try
            Result.Ok (of_string s)
          with Invalid_argument _ ->
            err "of_string failed"
        end
    | _ -> err "Not a JSON string"

let ulong =
  ulong_typ "ulong"

module Data = Pkcs11_hex_data

module Session_handle =
struct
  type t = Pkcs11.CK_SESSION_HANDLE.t
  let of_yojson = ulong_of_yojson
  let to_yojson = ulong_to_yojson
  let to_string = Unsigned.ULong.to_string
  let typ = ulong_typ "session_handle"
  let equal a b = Unsigned.ULong.compare a b = 0
  let hash x = Unsigned.ULong.to_int x
end

module Object_handle =
struct
  type t = Pkcs11.CK_OBJECT_HANDLE.t
  let to_string = Unsigned.ULong.to_string
  let to_yojson = ulong_to_yojson
  let of_yojson = ulong_of_yojson
  let compare = Unsigned.ULong.compare
  let typ = ulong_typ "object_handle"
end

module HW_feature_type =
struct
  type t = Pkcs11.CK_HW_FEATURE_TYPE.t
  let to_string = Unsigned.ULong.to_string
end

module Slot = struct
  type t =
    | Index of int
    | Id of int
    | Description of string
    | Label of string

  let to_yojson = function
    | Index x -> `List [`String "index"; `Int x]
    | Id x -> `List [`String "id"; `Int x]
    | Description x -> `List [`String "description"; `String x]
    | Label x -> `List [`String "label"; `String x]

  let of_yojson = function
    | `List [`String "index" ; `Int x] -> Result.Ok (Index x)
    | `List [`String "id" ; `Int x] -> Result.Ok (Id x)
    | `List [`String "description" ; `String x] -> Result.Ok (Description x)
    | `List [`String "label" ; `String x] -> Result.Ok (Label x)
    | _ -> Result.Error "Slot.t"

  let default = Index 0

  let to_string = function
    | Index i -> "slot index", string_of_int i
    | Id i -> "slot ID", string_of_int i
    | Description s -> "slot description", s
    | Label s -> "token label", s

  let invalid_slot_msg slot =
    let slot_type, value = to_string slot in
      Printf.sprintf
        "No %s matches %s."
        slot_type value
end

module Slot_id =
struct
  type t = Pkcs11.CK_SLOT_ID.t
  let compare = Unsigned.ULong.compare
  let to_string = Unsigned.ULong.to_string
  let equal a b = Unsigned.ULong.compare a b = 0
  let hash  = Unsigned.ULong.to_int
  let typ = ulong_typ "slot_id"
  let to_yojson = Record.Type.to_yojson typ
  let of_yojson = Record.Type.of_yojson typ
end

module Flags =
struct
  include Pkcs11.CK_FLAGS

  let to_json ?pretty (flags:t) =
    match pretty with
      | None ->
          ulong_to_yojson flags
      | Some pretty ->
          `Assoc [
            "value", ulong_to_yojson flags;
            "string", `String (pretty flags);
          ]

  type has_value =
    { value : Yojson.Safe.json
    ; string : string
    }
  [@@deriving of_yojson]

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    (* We know that [ulong_to_yojson] does not produce [`Assoc]s. *)
    let actual_json = match has_value_of_yojson json with
      | Result.Ok { value } -> value
      | Result.Error _ -> json
    in
    ulong_of_yojson actual_json

  let to_yojson =
    to_json ?pretty:None
end

module Object_class =
struct
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


  let equal = (Pervasives.(=): t -> t -> bool)
  let compare = (Pervasives.compare: t -> t -> int)

  let to_string = Pkcs11.CK_OBJECT_CLASS.to_string
  let of_string = Pkcs11.CK_OBJECT_CLASS.of_string

  let to_yojson object_class =
    `String (to_string object_class)

  let of_yojson = of_json_string ~typename:"object class" of_string

  let typ =
    Record.Type.make
      ~name:"object_class"
      ~of_yojson
      ~to_yojson
      ()
end

module Key_type =
struct
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
    | CKK_CS_UNKNOWN of Unsigned.ULong.t

  let equal = Pkcs11.CK_KEY_TYPE.equal
  let compare = Pkcs11.CK_KEY_TYPE.compare
  let to_string = Pkcs11.CK_KEY_TYPE.to_string
  let of_string = Pkcs11.CK_KEY_TYPE.of_string

  let to_yojson key_type =
    `String (to_string key_type)

  let of_yojson = of_json_string ~typename:"key type" of_string

  let typ =
    Record.Type.make
      ~name: "key_type"
      ~to_yojson
      ~of_yojson
      ()
end

module Version =
struct
  type t = Pkcs11.CK_VERSION.u = { major : int; minor : int; }
  [@@deriving yojson]

  let to_string = Pkcs11.CK_VERSION.to_string
end

module Bigint = Pkcs11.CK_BIGINT

module RV =
struct
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

  let compare x y = Pkcs11.CK_RV.compare x y
  let equal x y = Pkcs11.CK_RV.equal x y
  let to_string : t -> string = Pkcs11.CK_RV.to_string
  let of_string : string -> t = Pkcs11.CK_RV.of_string
end

module Mechanism_type =
struct
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

  let to_string = Pkcs11.CK_MECHANISM_TYPE.to_string
  let of_string = Pkcs11.CK_MECHANISM_TYPE.of_string
  let compare = Pkcs11.CK_MECHANISM_TYPE.compare
  let equal = Pkcs11.CK_MECHANISM_TYPE.equal

  let elements = Pkcs11.CK_MECHANISM_TYPE.elements

  let to_yojson mechanism_type =
    try
      `String (to_string mechanism_type)
    with Invalid_argument _ ->
      `Null

  let of_yojson = of_json_string ~typename:"mechanism type" of_string

  let typ =
    Record.Type.make
      ~name:"CK_MECHANISM_TYPE"
      ~to_yojson
      ~of_yojson
      ()
end

module Key_gen_mechanism =
struct
  open Pkcs11.Key_gen_mechanism

  type t = Pkcs11.Key_gen_mechanism.u =
    | CKM of Mechanism_type.t
    | CK_UNAVAILABLE_INFORMATION

  let to_yojson mechanism_type =
    try
      `String (to_string mechanism_type)
    with Invalid_argument _ ->
      `Null

  let of_yojson = of_json_string ~typename:"keygen mechanism" of_string

  let typ : t Record.Type.t =
    Record.Type.make
      ~name: "key_gen_mechanism"
      ~to_yojson
      ~of_yojson
      ()
end
module RSA_PKCS_MGF_type =
struct
  include Pkcs11.CK_RSA_PKCS_MGF_TYPE

  let to_json key_type =
    try
      `String (to_string key_type)
    with Invalid_argument _ ->
      `Null

  let to_yojson = to_json
  let of_yojson = of_json_string ~typename:"MGF type" of_string
end

module RSA_PKCS_OAEP_params =
struct
  type t = Pkcs11.CK_RSA_PKCS_OAEP_PARAMS.u =
    {
      hashAlg: Mechanism_type.t;
      mgf: RSA_PKCS_MGF_type.t;
      src: Data.t option;
    }
    [@@deriving yojson]
end

module RSA_PKCS_PSS_params =
struct
  type t = Pkcs11.CK_RSA_PKCS_PSS_PARAMS.u =
    {
      hashAlg: Mechanism_type.t;
      mgf: RSA_PKCS_MGF_type.t;
      sLen: ulong;
    }
    [@@deriving yojson]
end

let string_of_yojson = Record.Type.(of_yojson string)

module AES_CBC_ENCRYPT_DATA_params =
struct
  type t = Pkcs11.CK_AES_CBC_ENCRYPT_DATA_PARAMS.u =
    {
      iv: string;
      data: string;
    }
    [@@deriving yojson]
end

module DES_CBC_ENCRYPT_DATA_params =
struct
  type t = Pkcs11.CK_DES_CBC_ENCRYPT_DATA_PARAMS.u =
    {
      iv: string;
      data: string;
    }
    [@@deriving yojson]
end

module PKCS5_PBKDF2_SALT_SOURCE_type =
struct
  type t = Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.u

  let to_string =
    Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.to_string

  let of_string =
    Pkcs11.CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.of_string

  let to_yojson salt_type =
    try
      `String (to_string salt_type)
    with Invalid_argument _ ->
      `Null

  let of_yojson = of_json_string ~typename:"salt source type" of_string
end

module PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_type =
struct
  type t = Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.u

  let to_string =
    Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.to_string

  let of_string =
    Pkcs11.CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.of_string

  let to_yojson prf_type =
    try
      `String (to_string prf_type)
    with Invalid_argument _ ->
      `Null

  let of_yojson = of_json_string ~typename:"random function type" of_string
end

module PKCS5_PBKD2_DATA_params =
struct
  type t = Pkcs11.CK_PKCS5_PBKD2_PARAMS.u =
    {
      saltSource: PKCS5_PBKDF2_SALT_SOURCE_type.t;
      saltSourceData: string option;
      iterations: int;
      prf: PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_type.t;
      prfData: string option;
      password: string;
    }
    [@@deriving yojson]
end

module RAW_PAYLOAD_params = struct
  type t = Pkcs11.CK_RAW_PAYLOAD.t

  type record =
    { mechanism: Mechanism_type.t
    ; data: Data.t
    }
  [@@deriving yojson]

  let to_yojson (ckm, data) =
    let mechanism = Pkcs11.CK_MECHANISM_TYPE.view ckm in
    record_to_yojson { mechanism ; data }

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    record_of_yojson json >>= fun { mechanism ; data } ->
    let mechanism_type = Pkcs11.CK_MECHANISM_TYPE.make mechanism in
    Result.Ok (mechanism_type, data)
end

module Mechanism =
struct
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
    | CKM_AES_MAC_GENERAL of ulong
    | CKM_AES_ECB_ENCRYPT_DATA of Data.t
    | CKM_AES_CBC_ENCRYPT_DATA of AES_CBC_ENCRYPT_DATA_params.t
    | CKM_DES_KEY_GEN
    | CKM_DES_ECB
    | CKM_DES_CBC of Data.t
    | CKM_DES_CBC_PAD of Data.t
    | CKM_DES_MAC
    | CKM_DES_MAC_GENERAL of ulong
    | CKM_DES_ECB_ENCRYPT_DATA of Data.t
    | CKM_DES_CBC_ENCRYPT_DATA of DES_CBC_ENCRYPT_DATA_params.t
    | CKM_DES3_KEY_GEN
    | CKM_DES3_ECB
    | CKM_DES3_CBC of Data.t
    | CKM_DES3_CBC_PAD of Data.t
    | CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL of ulong
    | CKM_DES3_ECB_ENCRYPT_DATA of Data.t
    | CKM_DES3_CBC_ENCRYPT_DATA of DES_CBC_ENCRYPT_DATA_params.t
    | CKM_CONCATENATE_BASE_AND_DATA of Data.t
    | CKM_CONCATENATE_DATA_AND_BASE of Data.t
    | CKM_XOR_BASE_AND_DATA of Data.t
    | CKM_EXTRACT_KEY_FROM_KEY of ulong
    | CKM_CONCATENATE_BASE_AND_KEY of Object_handle.t
    | CKM_EC_KEY_PAIR_GEN
    | CKM_ECDSA
    | CKM_ECDSA_SHA1
    | CKM_ECDH1_DERIVE of Pkcs11.CK_ECDH1_DERIVE_PARAMS.u
    | CKM_ECDH1_COFACTOR_DERIVE of Pkcs11.CK_ECDH1_DERIVE_PARAMS.u
    | CKM_ECMQV_DERIVE of Pkcs11.CK_ECMQV_DERIVE_PARAMS.u
    | CKM_PKCS5_PBKD2 of PKCS5_PBKD2_DATA_params.t
    | CKM_CS_UNKNOWN of RAW_PAYLOAD_params.t

  let to_json =
    let simple name = `String name in
    let param name param json_of_param = `Assoc [ name, json_of_param param ] in
    let ulong name p = param name p ulong_to_yojson in
    function
      | CKM_SHA_1 ->
          simple "CKM_SHA_1"
      | CKM_SHA224 ->
          simple "CKM_SHA224"
      | CKM_SHA256 ->
          simple "CKM_SHA256"
      | CKM_SHA512 ->
          simple "CKM_SHA512"
      | CKM_MD5 ->
          simple "CKM_MD5"
      | CKM_RSA_PKCS_KEY_PAIR_GEN ->
          simple "CKM_RSA_PKCS_KEY_PAIR_GEN"
      | CKM_RSA_X9_31_KEY_PAIR_GEN ->
          simple "CKM_RSA_X9_31_KEY_PAIR_GEN"
      | CKM_RSA_PKCS ->
          simple "CKM_RSA_PKCS"
      | CKM_RSA_PKCS_OAEP p ->
          param "CKM_RSA_PKCS_OAEP" p RSA_PKCS_OAEP_params.to_yojson
      | CKM_RSA_X_509 ->
          simple "CKM_RSA_X_509"
      | CKM_RSA_PKCS_PSS p ->
          param "CKM_RSA_PKCS_PSS" p RSA_PKCS_PSS_params.to_yojson
      | CKM_SHA1_RSA_PKCS ->
          simple "CKM_SHA1_RSA_PKCS"
      | CKM_SHA224_RSA_PKCS ->
          simple "CKM_SHA224_RSA_PKCS"
      | CKM_SHA256_RSA_PKCS ->
          simple "CKM_SHA256_RSA_PKCS"
      | CKM_SHA384_RSA_PKCS ->
          simple "CKM_SHA384_RSA_PKCS"
      | CKM_SHA512_RSA_PKCS ->
          simple "CKM_SHA512_RSA_PKCS"
      | CKM_SHA1_RSA_PKCS_PSS p ->
          param "CKM_SHA1_RSA_PKCS_PSS" p RSA_PKCS_PSS_params.to_yojson
      | CKM_SHA224_RSA_PKCS_PSS p ->
          param "CKM_SHA224_RSA_PKCS_PSS" p RSA_PKCS_PSS_params.to_yojson
      | CKM_SHA256_RSA_PKCS_PSS p ->
          param "CKM_SHA256_RSA_PKCS_PSS" p RSA_PKCS_PSS_params.to_yojson
      | CKM_SHA384_RSA_PKCS_PSS p ->
          param "CKM_SHA384_RSA_PKCS_PSS" p RSA_PKCS_PSS_params.to_yojson
      | CKM_SHA512_RSA_PKCS_PSS p ->
          param "CKM_SHA512_RSA_PKCS_PSS" p RSA_PKCS_PSS_params.to_yojson
      | CKM_AES_KEY_GEN ->
          simple "CKM_AES_KEY_GEN"
      | CKM_AES_ECB ->
          simple "CKM_AES_ECB"
      | CKM_AES_CBC p ->
          param "CKM_AES_CBC" p Data.to_yojson
      | CKM_AES_CBC_PAD p ->
          param "CKM_AES_CBC_PAD" p Data.to_yojson
      | CKM_AES_MAC ->
          simple "CKM_AES_MAC"
      | CKM_AES_MAC_GENERAL p ->
          ulong "CKM_AES_MAC_GENERAL" p
      | CKM_AES_ECB_ENCRYPT_DATA p ->
          param "CKM_AES_ECB_ENCRYPT_DATA" p Data.to_yojson
      | CKM_AES_CBC_ENCRYPT_DATA p ->
          param "CKM_AES_CBC_ENCRYPT_DATA" p AES_CBC_ENCRYPT_DATA_params.to_yojson
      | CKM_DES_KEY_GEN ->
          simple "CKM_DES_KEY_GEN"
      | CKM_DES_ECB ->
          simple "CKM_DES_ECB"
      | CKM_DES_CBC p ->
          param "CKM_DES_CBC" p Data.to_yojson
      | CKM_DES_CBC_PAD p ->
          param "CKM_DES_CBC_PAD" p Data.to_yojson
      | CKM_DES_MAC ->
          simple "CKM_DES_MAC"
      | CKM_DES_MAC_GENERAL p ->
          ulong "CKM_DES_MAC_GENERAL" p
      | CKM_DES_ECB_ENCRYPT_DATA p ->
          param "CKM_DES_ECB_ENCRYPT_DATA" p Data.to_yojson
      | CKM_DES_CBC_ENCRYPT_DATA p ->
          param "CKM_DES_CBC_ENCRYPT_DATA" p DES_CBC_ENCRYPT_DATA_params.to_yojson
      | CKM_DES3_KEY_GEN ->
          simple "CKM_DES3_KEY_GEN"
      | CKM_DES3_ECB ->
          simple "CKM_DES3_ECB"
      | CKM_DES3_CBC p ->
          param "CKM_DES3_CBC" p Data.to_yojson
      | CKM_DES3_CBC_PAD p ->
          param "CKM_DES3_CBC_PAD" p Data.to_yojson
      | CKM_DES3_MAC ->
          simple "CKM_DES3_MAC"
      | CKM_DES3_MAC_GENERAL p ->
          ulong "CKM_DES3_MAC_GENERAL" p
      | CKM_DES3_ECB_ENCRYPT_DATA p ->
          param "CKM_DES3_ECB_ENCRYPT_DATA" p Data.to_yojson
      | CKM_DES3_CBC_ENCRYPT_DATA p ->
          param "CKM_DES3_CBC_ENCRYPT_DATA" p
            DES_CBC_ENCRYPT_DATA_params.to_yojson
      | CKM_CONCATENATE_BASE_AND_DATA p ->
          param "CKM_CONCATENATE_BASE_AND_DATA" p Data.to_yojson
      | CKM_CONCATENATE_DATA_AND_BASE p ->
          param "CKM_CONCATENATE_DATA_AND_BASE" p Data.to_yojson
      | CKM_XOR_BASE_AND_DATA p ->
          param "CKM_XOR_BASE_AND_DATA" p Data.to_yojson
      | CKM_EXTRACT_KEY_FROM_KEY p ->
          ulong "CKM_EXTRACT_KEY_FROM_KEY" p
      | CKM_CONCATENATE_BASE_AND_KEY p ->
          param "CKM_CONCATENATE_BASE_AND_KEY" p Object_handle.to_yojson
      | CKM_EC_KEY_PAIR_GEN ->
          simple "CKM_EC_KEY_PAIR_GEN"
      | CKM_ECDSA ->
          simple "CKM_ECDSA"
      | CKM_ECDSA_SHA1 ->
          simple "CKM_ECDSA_SHA1"
      | CKM_ECDH1_DERIVE p ->
          param "CKM_ECDH1_DERIVE" p Pkcs11.CK_ECDH1_DERIVE_PARAMS.u_to_yojson
      | CKM_ECDH1_COFACTOR_DERIVE p ->
          param "CKM_ECDH1_COFACTOR_DERIVE" p Pkcs11.CK_ECDH1_DERIVE_PARAMS.u_to_yojson
      | CKM_ECMQV_DERIVE p ->
          param "CKM_ECMQV_DERIVE" p Pkcs11.CK_ECMQV_DERIVE_PARAMS.u_to_yojson
      | CKM_PKCS5_PBKD2 p ->
          param "CKM_PKCS5_PBKD2" p PKCS5_PBKD2_DATA_params.to_yojson
      | CKM_CS_UNKNOWN p ->
          param "CKM_NOT_IMPLEMENTED" p RAW_PAYLOAD_params.to_yojson

  let of_yojson json =
    let parse name param =
      let simple ckm =
        if param = `Null then
          Result.Ok ckm
        else
          Result.Error "Mechanism does not expect a parameter"
      in
      let open Ppx_deriving_yojson_runtime in
      let oaep make = RSA_PKCS_OAEP_params.of_yojson param >>= fun r -> Result.Ok (make r) in
      let pbkd2 make = PKCS5_PBKD2_DATA_params.of_yojson param >>= fun r -> Result.Ok (make r) in
      let pss make = RSA_PKCS_PSS_params.of_yojson param >>= fun r -> Result.Ok (make r) in
      let data make = Data.of_yojson param >>= fun r -> Result.Ok (make r) in
      match name with
        | "CKM_SHA_1" -> simple CKM_SHA_1
        | "CKM_SHA224" -> simple CKM_SHA224
        | "CKM_SHA256" -> simple CKM_SHA256
        | "CKM_SHA512" -> simple CKM_SHA512
        | "CKM_MD5" -> simple CKM_MD5
        | "CKM_RSA_PKCS_KEY_PAIR_GEN" -> simple CKM_RSA_PKCS_KEY_PAIR_GEN
        | "CKM_RSA_X9_31_KEY_PAIR_GEN" -> simple CKM_RSA_X9_31_KEY_PAIR_GEN
        | "CKM_RSA_PKCS" -> simple CKM_RSA_PKCS
        | "CKM_RSA_PKCS_OAEP" -> oaep (fun x -> CKM_RSA_PKCS_OAEP x)
        | "CKM_PKCS5_PBKD2" -> pbkd2 (fun x -> CKM_PKCS5_PBKD2 x)
        | "CKM_RSA_X_509" -> simple CKM_RSA_X_509
        | "CKM_RSA_PKCS_PSS" -> pss (fun x -> CKM_RSA_PKCS_PSS x)
        | "CKM_SHA1_RSA_PKCS" -> simple CKM_SHA1_RSA_PKCS
        | "CKM_SHA224_RSA_PKCS" -> simple CKM_SHA224_RSA_PKCS
        | "CKM_SHA256_RSA_PKCS" -> simple CKM_SHA256_RSA_PKCS
        | "CKM_SHA384_RSA_PKCS" -> simple CKM_SHA384_RSA_PKCS
        | "CKM_SHA512_RSA_PKCS" -> simple CKM_SHA512_RSA_PKCS
        | "CKM_SHA1_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA1_RSA_PKCS_PSS x)
        | "CKM_SHA224_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA224_RSA_PKCS_PSS x)
        | "CKM_SHA256_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA256_RSA_PKCS_PSS x)
        | "CKM_SHA384_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA384_RSA_PKCS_PSS x)
        | "CKM_SHA512_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA512_RSA_PKCS_PSS x)
        | "CKM_AES_KEY_GEN" -> simple CKM_AES_KEY_GEN
        | "CKM_AES_ECB" -> simple CKM_AES_ECB
        | "CKM_AES_CBC" -> data (fun x -> CKM_AES_CBC x)
        | "CKM_AES_CBC_PAD" -> data (fun x -> CKM_AES_CBC_PAD x)
        | "CKM_AES_MAC" -> simple CKM_AES_MAC
        | "CKM_AES_MAC_GENERAL" ->
            ulong_of_yojson param >>= fun r -> Result.Ok (CKM_AES_MAC_GENERAL r)
        | "CKM_AES_ECB_ENCRYPT_DATA" ->
            data (fun x -> CKM_AES_ECB_ENCRYPT_DATA x)
        | "CKM_AES_CBC_ENCRYPT_DATA" ->
            AES_CBC_ENCRYPT_DATA_params.of_yojson param >>= fun r -> Result.Ok (CKM_AES_CBC_ENCRYPT_DATA r)
        | "CKM_DES_KEY_GEN" -> simple CKM_DES_KEY_GEN
        | "CKM_DES_ECB" -> simple CKM_DES_ECB
        | "CKM_DES_CBC" -> data (fun x -> CKM_DES_CBC x)
        | "CKM_DES_CBC_PAD" -> data (fun x -> CKM_DES_CBC_PAD x)
        | "CKM_DES_MAC" -> simple CKM_DES_MAC
        | "CKM_DES_MAC_GENERAL" ->
            ulong_of_yojson param >>= fun r -> Result.Ok (CKM_DES_MAC_GENERAL r)
        | "CKM_DES_ECB_ENCRYPT_DATA" ->
            data (fun x -> CKM_DES_ECB_ENCRYPT_DATA x)
        | "CKM_DES_CBC_ENCRYPT_DATA" ->
            DES_CBC_ENCRYPT_DATA_params.of_yojson param >>= fun r -> Result.Ok (CKM_DES_CBC_ENCRYPT_DATA r)
        | "CKM_DES3_KEY_GEN" -> simple CKM_DES3_KEY_GEN
        | "CKM_DES3_ECB" -> simple CKM_DES3_ECB
        | "CKM_DES3_CBC" -> data (fun x -> CKM_DES3_CBC x)
        | "CKM_DES3_CBC_PAD" -> data (fun x -> CKM_DES3_CBC_PAD x)
        | "CKM_DES3_MAC" -> simple CKM_DES3_MAC
        | "CKM_DES3_MAC_GENERAL" ->
            ulong_of_yojson param >>= fun r -> Result.Ok (CKM_DES3_MAC_GENERAL r)
        | "CKM_DES3_ECB_ENCRYPT_DATA" ->
            data (fun x -> CKM_DES3_ECB_ENCRYPT_DATA x)
        | "CKM_DES3_CBC_ENCRYPT_DATA" ->
            DES_CBC_ENCRYPT_DATA_params.of_yojson param >>= fun r -> Result.Ok (CKM_DES3_CBC_ENCRYPT_DATA r)
        | "CKM_CONCATENATE_BASE_AND_DATA" ->
            data (fun x -> CKM_CONCATENATE_BASE_AND_DATA x)
        | "CKM_CONCATENATE_DATA_AND_BASE" ->
            data (fun x -> CKM_CONCATENATE_DATA_AND_BASE x)
        | "CKM_XOR_BASE_AND_DATA" ->
            data (fun x -> CKM_XOR_BASE_AND_DATA x)
        | "CKM_EXTRACT_KEY_FROM_KEY" ->
            ulong_of_yojson param >>= fun r -> Result.Ok (CKM_EXTRACT_KEY_FROM_KEY r)
        | "CKM_CONCATENATE_BASE_AND_KEY" ->
            Object_handle.of_yojson param >>= fun r -> Result.Ok (CKM_CONCATENATE_BASE_AND_KEY r)
        | "CKM_EC_KEY_PAIR_GEN" -> simple CKM_EC_KEY_PAIR_GEN
        | "CKM_ECDSA" -> simple CKM_ECDSA
        | "CKM_ECDSA_SHA1" -> simple CKM_ECDSA_SHA1
        | "CKM_ECDH1_DERIVE" ->
            Pkcs11.CK_ECDH1_DERIVE_PARAMS.u_of_yojson param >>= fun r -> Result.Ok (CKM_ECDH1_DERIVE r)
        | _ ->
            begin
              RAW_PAYLOAD_params.of_yojson param >>= fun params ->
              Result.Ok (CKM_CS_UNKNOWN params)
            end
    in
    match json with
      | `Assoc [ name, param ] ->
          parse name param
      | `String name ->
          parse name `Null
      | _ ->
          Result.Error "Ill-formed mechanism"

  let to_yojson = to_json

  let typ =
    Record.Type.make
      ~name: "mechanism"
      ~to_yojson
      ~of_yojson
      ()

  let mechanism_type = Pkcs11.CK_MECHANISM.mechanism_type
  let compare = Pkcs11.CK_MECHANISM.compare

  let of_raw t = Pkcs11.CK_MECHANISM.view t

  (* Kinds are "tags" on mechanisms which describe how they can be
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

  (* There are three ways to structure this function: following the
     numbering of mechanisms in the pkcs11 header, following the
     structure of table 34, or grouping the mechanism that are similar
     together.  Since all the solutions have drawbacks, we chose here to
     follow the numbering of values in the header, to make it easier to
     add new values. *)
  let kinds m =
    let open Pkcs11.CK_MECHANISM_TYPE in
    match mechanism_type m with
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
  let is ks m =
    let kinds = kinds m in
    List.for_all (fun k -> List.mem k kinds) ks

  let key_type = function
    | CKM_AES_KEY_GEN
      -> Some Key_type.CKK_AES
    | CKM_DES_KEY_GEN
      -> Some Key_type.CKK_DES
    | CKM_DES3_KEY_GEN
      -> Some Key_type.CKK_DES3
    | CKM_RSA_PKCS_KEY_PAIR_GEN
      -> Some Key_type.CKK_RSA
    | CKM_RSA_X9_31_KEY_PAIR_GEN
      -> Some Key_type.CKK_RSA
    | CKM_EC_KEY_PAIR_GEN
      -> Some Key_type.CKK_EC
    | CKM_SHA_1
    | CKM_SHA224
    | CKM_SHA256
    | CKM_SHA512
    | CKM_MD5
    | CKM_RSA_PKCS
    | CKM_RSA_X_509
    | CKM_RSA_PKCS_OAEP _
    | CKM_RSA_PKCS_PSS _
    | CKM_SHA1_RSA_PKCS
    | CKM_SHA224_RSA_PKCS
    | CKM_SHA256_RSA_PKCS
    | CKM_SHA384_RSA_PKCS
    | CKM_SHA512_RSA_PKCS
    | CKM_SHA1_RSA_PKCS_PSS _
    | CKM_SHA224_RSA_PKCS_PSS _
    | CKM_SHA256_RSA_PKCS_PSS _
    | CKM_SHA384_RSA_PKCS_PSS _
    | CKM_SHA512_RSA_PKCS_PSS _
    | CKM_ECDSA
    | CKM_ECDSA_SHA1
    | CKM_ECDH1_DERIVE _
    | CKM_ECDH1_COFACTOR_DERIVE _
    | CKM_ECMQV_DERIVE _
    | CKM_DES_ECB
    | CKM_DES_CBC _
    | CKM_DES_CBC_PAD _
    | CKM_DES3_ECB
    | CKM_DES3_CBC _
    | CKM_DES3_CBC_PAD _
    | CKM_AES_ECB
    | CKM_AES_CBC _
    | CKM_AES_CBC_PAD _
    | CKM_DES_MAC
    | CKM_DES_MAC_GENERAL _
    | CKM_DES3_MAC
    | CKM_DES3_MAC_GENERAL _
    | CKM_AES_MAC
    | CKM_AES_MAC_GENERAL _
    | CKM_AES_ECB_ENCRYPT_DATA _
    | CKM_AES_CBC_ENCRYPT_DATA _
    | CKM_DES_ECB_ENCRYPT_DATA _
    | CKM_DES_CBC_ENCRYPT_DATA _
    | CKM_DES3_ECB_ENCRYPT_DATA _
    | CKM_DES3_CBC_ENCRYPT_DATA _
    | CKM_CONCATENATE_BASE_AND_DATA _
    | CKM_CONCATENATE_DATA_AND_BASE _
    | CKM_EXTRACT_KEY_FROM_KEY _
    | CKM_CONCATENATE_BASE_AND_KEY _
    | CKM_XOR_BASE_AND_DATA _
    | CKM_PKCS5_PBKD2 _
    | CKM_CS_UNKNOWN _ ->
      None

  let to_string x = mechanism_type x |> Mechanism_type.to_string
  let pp fmt m = Format.fprintf fmt "%s" @@ to_string m
end

module User_type =
struct
  type t = Pkcs11.CK_USER_TYPE.u =
    | CKU_SO
    | CKU_USER
    | CKU_CONTEXT_SPECIFIC
    | CKU_CS_UNKNOWN of Unsigned.ULong.t

  let compare x y = Pkcs11.CK_USER_TYPE.compare x y
  let equal x y = Pkcs11.CK_USER_TYPE.equal x y
  let to_string : t -> string = Pkcs11.CK_USER_TYPE.to_string
  let of_string : string -> t = Pkcs11.CK_USER_TYPE.of_string

  let to_yojson user_type =
    `String (to_string user_type)

  let of_yojson = of_json_string ~typename:"user type" of_string
end

module Info =
struct
  type t = Pkcs11.CK_INFO.u =
    {
      cryptokiVersion : Version.t;
      manufacturerID : string;
      flags : Flags.t;
      libraryDescription : string;
      libraryVersion : Version.t;
    }
    [@@deriving of_yojson]

  let to_string = Pkcs11.CK_INFO.to_string
  let to_strings = Pkcs11.CK_INFO.to_strings
  let flags_to_string = Pkcs11.CK_INFO.string_of_flags

  let to_yojson info =
    `Assoc [
      "cryptokiVersion", Version.to_yojson info.cryptokiVersion;
      "manufacturerID", `String info.manufacturerID;
      "flags", Flags.to_json ~pretty:flags_to_string info.flags;
      "libraryDescription", `String info.libraryDescription;
      "libraryVersion", Version.to_yojson info.libraryVersion;
    ]

  let typ =
    Record.Type.make
      ~name: "CK_INFO"
      ~to_yojson
      ~of_yojson
      ()
end

module Token_info =
struct
  type t = Pkcs11.CK_TOKEN_INFO.u =
    {
      label : string;
      manufacturerID : string;
      model : string;
      serialNumber : string;
      flags : Flags.t;
      ulMaxSessionCount : ulong;
      ulSessionCount : ulong;
      ulMaxRwSessionCount : ulong;
      ulRwSessionCount : ulong;
      ulMaxPinLen : ulong;
      ulMinPinLen : ulong;
      ulTotalPublicMemory : ulong;
      ulFreePublicMemory : ulong;
      ulTotalPrivateMemory : ulong;
      ulFreePrivateMemory : ulong;
      hardwareVersion : Version.t;
      firmwareVersion : Version.t;
      utcTime : string;
    }
    [@@deriving of_yojson]

  let ul_to_string = Pkcs11.CK_TOKEN_INFO.ul_to_string
  let to_string = Pkcs11.CK_TOKEN_INFO.to_string
  let to_strings = Pkcs11.CK_TOKEN_INFO.to_strings
  let flags_to_string = Pkcs11.CK_TOKEN_INFO.string_of_flags

  let to_yojson info =
    let ulong x = `String (Unsigned.ULong.to_string x) in
    `Assoc [
      "label", `String info.label;
      "manufacturerID", `String info.manufacturerID;
      "model", `String info.model;
      "serialNumber", `String info.serialNumber;
      "flags",
      Flags.to_json ~pretty:flags_to_string info.flags;
      "ulMaxSessionCount", ulong info.ulMaxSessionCount;
      "ulSessionCount", ulong info.ulSessionCount;
      "ulMaxRwSessionCount", ulong info.ulMaxRwSessionCount;
      "ulRwSessionCount", ulong info.ulRwSessionCount;
      "ulMaxPinLen", ulong info.ulMaxPinLen;
      "ulMinPinLen", ulong info.ulMinPinLen;
      "ulTotalPublicMemory", ulong info.ulTotalPublicMemory;
      "ulFreePublicMemory", ulong info.ulFreePublicMemory;
      "ulTotalPrivateMemory", ulong info.ulTotalPrivateMemory;
      "ulFreePrivateMemory", ulong info.ulFreePrivateMemory;
      "hardwareVersion", Version.to_yojson info.hardwareVersion;
      "firmwareVersion", Version.to_yojson info.firmwareVersion;
      "utcTime", `String info.utcTime;
    ]

  let typ =
    Record.Type.make
      ~name: "CK_TOKEN_INFO"
      ~to_yojson
      ~of_yojson
      ()
end

module Slot_info =
struct
  type t = Pkcs11.CK_SLOT_INFO.u =
    {
      slotDescription : string;
      manufacturerID : string;
      flags : Flags.t;
      hardwareVersion : Version.t;
      firmwareVersion : Version.t;
    }
    [@@deriving of_yojson]

  let to_string = Pkcs11.CK_SLOT_INFO.to_string
  let to_strings = Pkcs11.CK_SLOT_INFO.to_strings
  let flags_to_string = Pkcs11.CK_SLOT_INFO.string_of_flags

  let to_yojson info =
    `Assoc [
      "slotDescription", `String info.slotDescription;
      "manufacturerID", `String info.manufacturerID;
      "flags",
      Flags.to_json ~pretty:flags_to_string info.flags;
      "hardwareVersion", Version.to_yojson info.hardwareVersion;
      "firmwareVersion", Version.to_yojson info.firmwareVersion;
    ]

  let typ =
    Record.Type.make
      ~name: "CK_SLOT_INFO"
      ~to_yojson
      ~of_yojson
      ()
end

module Mechanism_info =
struct
  type t = Pkcs11.CK_MECHANISM_INFO.u =
    {
      ulMinKeySize : ulong;
      ulMaxKeySize : ulong;
      flags : Flags.t;
    }
    [@@deriving of_yojson]

  let to_string = Pkcs11.CK_MECHANISM_INFO.to_string
  let to_strings = Pkcs11.CK_MECHANISM_INFO.to_strings
  let flags_to_string = Pkcs11.CK_MECHANISM_INFO.string_of_flags
  let flags_to_strings = Pkcs11.CK_MECHANISM_INFO.strings_of_flags
  let allowed_flags = Pkcs11.CK_MECHANISM_INFO.allowed_flags

  let to_yojson info =
    `Assoc [
      "ulMinKeySize", `String (info.ulMinKeySize |> Unsigned.ULong.to_string );
      "ulMaxKeySize", `String (info.ulMaxKeySize |> Unsigned.ULong.to_string );
      "flags",
      Flags.to_json ~pretty:flags_to_string info.flags;
    ]

  let typ =
    Record.Type.make
      ~name: "CK_MECHANISM_INFO"
      ~to_yojson
      ~of_yojson
      ()
end

module Session_info =
struct
  type t = Pkcs11.CK_SESSION_INFO.u =
    {
      slotID : ulong;
      state : ulong;
      flags : Flags.t;
      ulDeviceError : ulong;
    }
    [@@deriving of_yojson]

  let to_string = Pkcs11.CK_SESSION_INFO.to_string
  let to_strings = Pkcs11.CK_SESSION_INFO.to_strings

  let to_yojson info =
    `Assoc [
      "slotID", `String (info.slotID |> Unsigned.ULong.to_string );
      "state", `String (info.state |> Unsigned.ULong.to_string);
      "flags",
      Flags.to_json ~pretty: Pkcs11.CK_SESSION_INFO.string_of_flags info.flags;
      "ulDeviceError", `String (info.ulDeviceError |> Unsigned.ULong.to_string);
    ]

  let typ =
    Record.Type.make
      ~name: "CK_SESSION_INFO"
      ~to_yojson
      ~of_yojson
      ()
end

module Attribute_type =
struct

  type not_implemented = Pkcs11.CK_ATTRIBUTE_TYPE.not_implemented = NOT_IMPLEMENTED of string

  type 'a t = 'a Pkcs11.CK_ATTRIBUTE_TYPE.u =
    | CKA_CLASS : Pkcs11.CK_OBJECT_CLASS.u t
    | CKA_TOKEN : bool t
    | CKA_PRIVATE : bool t
    | CKA_LABEL : string t
    | CKA_APPLICATION : not_implemented t
    | CKA_VALUE : string t
    | CKA_OBJECT_ID : not_implemented t
    | CKA_CERTIFICATE_TYPE : not_implemented t
    | CKA_ISSUER : not_implemented t
    | CKA_SERIAL_NUMBER : not_implemented t
    | CKA_AC_ISSUER : not_implemented t
    | CKA_OWNER : not_implemented t
    | CKA_ATTR_TYPES : not_implemented t
    | CKA_TRUSTED : bool t
    | CKA_CERTIFICATE_CATEGORY : not_implemented t
    | CKA_JAVA_MIDP_SECURITY_DOMAIN : not_implemented t
    | CKA_URL : not_implemented t
    | CKA_HASH_OF_SUBJECT_PUBLIC_KEY : not_implemented t
    | CKA_HASH_OF_ISSUER_PUBLIC_KEY : not_implemented t
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
    | CKA_BASE : not_implemented t
    | CKA_PRIME_BITS : Pkcs11.CK_ULONG.t t
    | CKA_SUBPRIME_BITS : Pkcs11.CK_ULONG.t t
    (* | CKA_SUB_PRIME_BITS : not_implemented t *)
    | CKA_VALUE_BITS : not_implemented t
    | CKA_VALUE_LEN : Pkcs11.CK_ULONG.t t
    | CKA_EXTRACTABLE : bool t
    | CKA_LOCAL : bool t
    | CKA_NEVER_EXTRACTABLE : bool t
    | CKA_ALWAYS_SENSITIVE : bool t
    | CKA_KEY_GEN_MECHANISM : Pkcs11.Key_gen_mechanism.u t
    | CKA_MODIFIABLE : bool t
    (* | CKA_ECDSA_PARAMS : string t *)
    | CKA_EC_PARAMS : Key_parsers.Asn1.EC.Params.t t
    | CKA_EC_POINT : Key_parsers.Asn1.EC.point t
    | CKA_SECONDARY_AUTH : not_implemented t
    | CKA_AUTH_PIN_FLAGS : not_implemented t
    | CKA_ALWAYS_AUTHENTICATE : bool t
    | CKA_WRAP_WITH_TRUSTED : bool t
    | CKA_WRAP_TEMPLATE : not_implemented t
    | CKA_UNWRAP_TEMPLATE : not_implemented t
    | CKA_OTP_FORMAT : not_implemented t
    | CKA_OTP_LENGTH : not_implemented t
    | CKA_OTP_TIME_INTERVAL : not_implemented t
    | CKA_OTP_USER_FRIENDLY_MODE : not_implemented t
    | CKA_OTP_CHALLENGE_REQUIREMENT : not_implemented t
    | CKA_OTP_TIME_REQUIREMENT : not_implemented t
    | CKA_OTP_COUNTER_REQUIREMENT : not_implemented t
    | CKA_OTP_PIN_REQUIREMENT : not_implemented t
    | CKA_OTP_COUNTER : not_implemented t
    | CKA_OTP_TIME : not_implemented t
    | CKA_OTP_USER_IDENTIFIER : not_implemented t
    | CKA_OTP_SERVICE_IDENTIFIER : not_implemented t
    | CKA_OTP_SERVICE_LOGO : not_implemented t
    | CKA_OTP_SERVICE_LOGO_TYPE : not_implemented t
    | CKA_HW_FEATURE_TYPE : not_implemented t
    | CKA_RESET_ON_INIT : not_implemented t
    | CKA_HAS_RESET : not_implemented t
    | CKA_PIXEL_X : not_implemented t
    | CKA_PIXEL_Y : not_implemented t
    | CKA_RESOLUTION : not_implemented t
    | CKA_CHAR_ROWS : not_implemented t
    | CKA_CHAR_COLUMNS : not_implemented t
    | CKA_COLOR : not_implemented t
    | CKA_BITS_PER_PIXEL : not_implemented t
    | CKA_CHAR_SETS : not_implemented t
    | CKA_ENCODING_METHODS : not_implemented t
    | CKA_MIME_TYPES : not_implemented t
    | CKA_MECHANISM_TYPE : not_implemented t
    | CKA_REQUIRED_CMS_ATTRIBUTES : not_implemented t
    | CKA_DEFAULT_CMS_ATTRIBUTES : not_implemented t
    | CKA_SUPPORTED_CMS_ATTRIBUTES : not_implemented t
    | CKA_ALLOWED_MECHANISMS : not_implemented t
    | CKA_VENDOR_DEFINED : not_implemented t
    | CKA_CS_UNKNOWN: Unsigned.ULong.t -> not_implemented t

  type pack = Pkcs11.CK_ATTRIBUTE_TYPE.pack = Pack : 'a t -> pack

  let compare = Pkcs11.CK_ATTRIBUTE_TYPE.compare
  let compare_pack = Pkcs11.CK_ATTRIBUTE_TYPE.compare_pack
  let to_string = Pkcs11.CK_ATTRIBUTE_TYPE.to_string
  let of_string = Pkcs11.CK_ATTRIBUTE_TYPE.of_string
  let equal = Pkcs11.CK_ATTRIBUTE_TYPE.equal
  let equal_pack = Pkcs11.CK_ATTRIBUTE_TYPE.equal_pack

  let to_json attribute =
    try
      `String (to_string attribute)
    with Invalid_argument _ ->
      `Null

  let pack_to_json (Pack attribute) = to_json attribute

  let pack_to_yojson = pack_to_json

  let pack_of_yojson = of_json_string ~typename:"attribute type" of_string

  let elements =
    [
      Pack CKA_CLASS;
      Pack CKA_TOKEN;
      Pack CKA_PRIVATE;
      Pack CKA_LABEL;
      Pack CKA_VALUE;
      Pack CKA_TRUSTED;
      Pack CKA_KEY_TYPE;
      Pack CKA_SUBJECT;
      Pack CKA_ID;
      Pack CKA_SENSITIVE;
      Pack CKA_ENCRYPT;
      Pack CKA_DECRYPT;
      Pack CKA_WRAP;
      Pack CKA_UNWRAP;
      Pack CKA_SIGN;
      Pack CKA_SIGN_RECOVER;
      Pack CKA_VERIFY;
      Pack CKA_VERIFY_RECOVER;
      Pack CKA_DERIVE;
      Pack CKA_MODULUS;
      Pack CKA_MODULUS_BITS;
      Pack CKA_PUBLIC_EXPONENT;
      Pack CKA_PRIVATE_EXPONENT;
      Pack CKA_PRIME_1;
      Pack CKA_PRIME_2;
      Pack CKA_EXPONENT_1;
      Pack CKA_EXPONENT_2;
      Pack CKA_COEFFICIENT;
      Pack CKA_PRIME;
      Pack CKA_SUBPRIME;
      Pack CKA_PRIME_BITS;
      Pack CKA_SUBPRIME_BITS;
      Pack CKA_VALUE_LEN;
      Pack CKA_EXTRACTABLE;
      Pack CKA_LOCAL;
      Pack CKA_NEVER_EXTRACTABLE;
      Pack CKA_ALWAYS_SENSITIVE;
      Pack CKA_KEY_GEN_MECHANISM;
      Pack CKA_MODIFIABLE;
      Pack CKA_EC_PARAMS;
      Pack CKA_EC_POINT;
      Pack CKA_ALWAYS_AUTHENTICATE;
      Pack CKA_WRAP_WITH_TRUSTED;
    ]

  let known_attribute_types = List.map (fun (Pack c) -> to_string c) elements
end

module Attribute =
struct

  type 'a t = 'a Attribute_type.t * 'a
  type pack = Pkcs11.CK_ATTRIBUTE.pack = Pack : 'a t -> pack

  let to_string = Pkcs11.CK_ATTRIBUTE.to_string
  let to_string_pair = Pkcs11.CK_ATTRIBUTE.to_string_pair

  (* Note: it is important for [Template.to_json] and [Template.of_json]
     that all attributes are represented using [`Assoc]. *)
  let to_json : type a . a t -> Yojson.Safe.json = fun attribute ->
    let open Attribute_type in
    let p json_of_param name param =
      `Assoc [ name, json_of_param param ]
    in
    let p_object_class = p Object_class.to_yojson in
    let p_bool : string -> bool -> Yojson.Safe.json =
      p @@ fun b -> `String (if b then "CK_TRUE" else "CK_FALSE") in
    let p_string : string -> string -> Yojson.Safe.json =
      p @@ fun s -> `String s in
    let p_data = p Data.to_yojson in
    let p_key_type = p Key_type.to_yojson in
    let p_ulong = p ulong_to_yojson in
    let p_bigint = p Pkcs11.CK_BIGINT.to_yojson in
    let p_mechanism_type = p Key_gen_mechanism.to_yojson in
    let p_ec_params = p Key_parsers.Asn1.EC.Params.to_yojson in
    let p_ec_point = p (fun cs -> Data.to_yojson @@ Cstruct.to_string cs)
    in
    match attribute with
      | CKA_CLASS, param ->
          p_object_class "CKA_CLASS" param
      | CKA_TOKEN, param ->
          p_bool "CKA_TOKEN" param
      | CKA_PRIVATE, param ->
          p_bool "CKA_PRIVATE" param
      | CKA_LABEL, param ->
          p_string "CKA_LABEL" param
      | CKA_VALUE, param ->
          p_data "CKA_VALUE" param
      | CKA_TRUSTED, param ->
          p_bool "CKA_TRUSTED" param
      | CKA_KEY_TYPE, param ->
          p_key_type "CKA_KEY_TYPE" param
      | CKA_SUBJECT, param ->
          p_string "CKA_SUBJECT" param
      | CKA_ID, param ->
          p_string "CKA_ID" param
      | CKA_SENSITIVE, param ->
          p_bool "CKA_SENSITIVE" param
      | CKA_ENCRYPT, param ->
          p_bool "CKA_ENCRYPT" param
      | CKA_DECRYPT, param ->
          p_bool "CKA_DECRYPT" param
      | CKA_WRAP, param ->
          p_bool "CKA_WRAP" param
      | CKA_UNWRAP, param ->
          p_bool "CKA_UNWRAP" param
      | CKA_SIGN, param ->
          p_bool "CKA_SIGN" param
      | CKA_SIGN_RECOVER, param ->
          p_bool "CKA_SIGN_RECOVER" param
      | CKA_VERIFY, param ->
          p_bool "CKA_VERIFY" param
      | CKA_VERIFY_RECOVER, param ->
          p_bool "CKA_VERIFY_RECOVER" param
      | CKA_DERIVE, param ->
          p_bool "CKA_DERIVE" param
      | CKA_MODULUS, param ->
          p_bigint "CKA_MODULUS" param
      | CKA_MODULUS_BITS, param ->
          p_ulong "CKA_MODULUS_BITS" param
      | CKA_PUBLIC_EXPONENT, param ->
          p_bigint "CKA_PUBLIC_EXPONENT" param
      | CKA_PRIVATE_EXPONENT, param ->
          p_bigint "CKA_PRIVATE_EXPONENT" param
      | CKA_PRIME_1, param ->
          p_bigint "CKA_PRIME_1" param
      | CKA_PRIME_2, param ->
          p_bigint "CKA_PRIME_2" param
      | CKA_EXPONENT_1, param ->
          p_bigint "CKA_EXPONENT_1" param
      | CKA_EXPONENT_2, param ->
          p_bigint "CKA_EXPONENT_2" param
      | CKA_COEFFICIENT, param ->
          p_bigint "CKA_COEFFICIENT" param
      | CKA_PRIME, param ->
          p_bigint "CKA_PRIME" param
      | CKA_SUBPRIME, param ->
          p_bigint "CKA_SUBPRIME" param
      | CKA_VALUE_LEN, param ->
          p_ulong "CKA_VALUE_LEN" param
      | CKA_EXTRACTABLE, param ->
          p_bool "CKA_EXTRACTABLE" param
      | CKA_LOCAL, param ->
          p_bool "CKA_LOCAL" param
      | CKA_NEVER_EXTRACTABLE, param ->
          p_bool "CKA_NEVER_EXTRACTABLE" param
      | CKA_ALWAYS_SENSITIVE, param ->
          p_bool "CKA_ALWAYS_SENSITIVE" param
      | CKA_KEY_GEN_MECHANISM, param ->
          p_mechanism_type "CKA_KEY_GEN_MECHANISM" param
      | CKA_MODIFIABLE, param ->
          p_bool "CKA_MODIFIABLE" param
      (* | CKA_ECDSA_PARAMS, param -> *)
      (*     p_data "CKA_ECDSA_PARAMS" param *)
      | CKA_EC_PARAMS, param ->
          p_ec_params "CKA_EC_PARAMS" param
      | CKA_EC_POINT, param ->
          p_ec_point "CKA_EC_POINT" param
      | CKA_ALWAYS_AUTHENTICATE, param ->
          p_bool "CKA_ALWAYS_AUTHENTICATE" param
      | CKA_WRAP_WITH_TRUSTED, param ->
          p_bool "CKA_WRAP_WITH_TRUSTED" param
      | CKA_APPLICATION, NOT_IMPLEMENTED param ->
          p_data "CKA_APPLICATION" param
      | CKA_OBJECT_ID, NOT_IMPLEMENTED param ->
          p_data "CKA_OBJECT_ID" param
      | CKA_CERTIFICATE_TYPE, NOT_IMPLEMENTED param ->
          p_data "CKA_CERTIFICATE_TYPE" param
      | CKA_ISSUER, NOT_IMPLEMENTED param ->
          p_data "CKA_ISSUER" param
      | CKA_SERIAL_NUMBER, NOT_IMPLEMENTED param ->
          p_data "CKA_SERIAL_NUMBER" param
      | CKA_AC_ISSUER, NOT_IMPLEMENTED param ->
          p_data "CKA_AC_ISSUER" param
      | CKA_OWNER, NOT_IMPLEMENTED param ->
          p_data "CKA_OWNER" param
      | CKA_ATTR_TYPES, NOT_IMPLEMENTED param ->
          p_data "CKA_ATTR_TYPES" param
      | CKA_CERTIFICATE_CATEGORY, NOT_IMPLEMENTED param ->
          p_data "CKA_CERTIFICATE_CATEGORY" param
      | CKA_JAVA_MIDP_SECURITY_DOMAIN, NOT_IMPLEMENTED param ->
          p_data "CKA_JAVA_MIDP_SECURITY_DOMAIN" param
      | CKA_URL, NOT_IMPLEMENTED param ->
          p_data "CKA_URL" param
      | CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NOT_IMPLEMENTED param ->
          p_data "CKA_HASH_OF_SUBJECT_PUBLIC_KEY" param
      | CKA_HASH_OF_ISSUER_PUBLIC_KEY, NOT_IMPLEMENTED param ->
          p_data "CKA_HASH_OF_ISSUER_PUBLIC_KEY" param
      | CKA_CHECK_VALUE, NOT_IMPLEMENTED param ->
          p_data "CKA_CHECK_VALUE" param
      | CKA_START_DATE, NOT_IMPLEMENTED param ->
          p_data "CKA_START_DATE" param
      | CKA_END_DATE, NOT_IMPLEMENTED param ->
          p_data "CKA_END_DATE" param
      | CKA_BASE, NOT_IMPLEMENTED param ->
          p_data "CKA_BASE" param
      | CKA_PRIME_BITS, param ->
          p_ulong "CKA_PRIME_BITS" param
      | CKA_SUBPRIME_BITS, param ->
          p_ulong "CKA_SUBPRIME_BITS" param
      (* | CKA_SUB_PRIME_BITS, NOT_IMPLEMENTED param -> *)
      (*     p_data "CKA_SUB_PRIME_BITS" param *)
      | CKA_VALUE_BITS, NOT_IMPLEMENTED param ->
          p_data "CKA_VALUE_BITS" param
      | CKA_SECONDARY_AUTH, NOT_IMPLEMENTED param ->
          p_data "CKA_SECONDARY_AUTH" param
      | CKA_AUTH_PIN_FLAGS, NOT_IMPLEMENTED param ->
          p_data "CKA_AUTH_PIN_FLAGS" param
      | CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED param ->
          p_data "CKA_WRAP_TEMPLATE" param
      | CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED param ->
          p_data "CKA_UNWRAP_TEMPLATE" param
      | CKA_OTP_FORMAT, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_FORMAT" param
      | CKA_OTP_LENGTH, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_LENGTH" param
      | CKA_OTP_TIME_INTERVAL, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_TIME_INTERVAL" param
      | CKA_OTP_USER_FRIENDLY_MODE, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_USER_FRIENDLY_MODE" param
      | CKA_OTP_CHALLENGE_REQUIREMENT, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_CHALLENGE_REQUIREMENT" param
      | CKA_OTP_TIME_REQUIREMENT, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_TIME_REQUIREMENT" param
      | CKA_OTP_COUNTER_REQUIREMENT, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_COUNTER_REQUIREMENT" param
      | CKA_OTP_PIN_REQUIREMENT, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_PIN_REQUIREMENT" param
      | CKA_OTP_COUNTER, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_COUNTER" param
      | CKA_OTP_TIME, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_TIME" param
      | CKA_OTP_USER_IDENTIFIER, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_USER_IDENTIFIER" param
      | CKA_OTP_SERVICE_IDENTIFIER, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_SERVICE_IDENTIFIER" param
      | CKA_OTP_SERVICE_LOGO, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_SERVICE_LOGO" param
      | CKA_OTP_SERVICE_LOGO_TYPE, NOT_IMPLEMENTED param ->
          p_data "CKA_OTP_SERVICE_LOGO_TYPE" param
      | CKA_HW_FEATURE_TYPE, NOT_IMPLEMENTED param ->
          p_data "CKA_HW_FEATURE_TYPE" param
      | CKA_RESET_ON_INIT, NOT_IMPLEMENTED param ->
          p_data "CKA_RESET_ON_INIT" param
      | CKA_HAS_RESET, NOT_IMPLEMENTED param ->
          p_data "CKA_HAS_RESET" param
      | CKA_PIXEL_X, NOT_IMPLEMENTED param ->
          p_data "CKA_PIXEL_X" param
      | CKA_PIXEL_Y, NOT_IMPLEMENTED param ->
          p_data "CKA_PIXEL_Y" param
      | CKA_RESOLUTION, NOT_IMPLEMENTED param ->
          p_data "CKA_RESOLUTION" param
      | CKA_CHAR_ROWS, NOT_IMPLEMENTED param ->
          p_data "CKA_CHAR_ROWS" param
      | CKA_CHAR_COLUMNS, NOT_IMPLEMENTED param ->
          p_data "CKA_CHAR_COLUMNS" param
      | CKA_COLOR, NOT_IMPLEMENTED param ->
          p_data "CKA_COLOR" param
      | CKA_BITS_PER_PIXEL, NOT_IMPLEMENTED param ->
          p_data "CKA_BITS_PER_PIXEL" param
      | CKA_CHAR_SETS, NOT_IMPLEMENTED param ->
          p_data "CKA_CHAR_SETS" param
      | CKA_ENCODING_METHODS, NOT_IMPLEMENTED param ->
          p_data "CKA_ENCODING_METHODS" param
      | CKA_MIME_TYPES, NOT_IMPLEMENTED param ->
          p_data "CKA_MIME_TYPES" param
      | CKA_MECHANISM_TYPE, NOT_IMPLEMENTED param ->
          p_data "CKA_MECHANISM_TYPE" param
      | CKA_REQUIRED_CMS_ATTRIBUTES, NOT_IMPLEMENTED param ->
          p_data "CKA_REQUIRED_CMS_ATTRIBUTES" param
      | CKA_DEFAULT_CMS_ATTRIBUTES, NOT_IMPLEMENTED param ->
          p_data "CKA_DEFAULT_CMS_ATTRIBUTES" param
      | CKA_SUPPORTED_CMS_ATTRIBUTES, NOT_IMPLEMENTED param ->
          p_data "CKA_SUPPORTED_CMS_ATTRIBUTES" param
      | CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED param ->
          p_data "CKA_ALLOWED_MECHANISMS" param
      | CKA_VENDOR_DEFINED, NOT_IMPLEMENTED param ->
          p_data "CKA_VENDOR_DEFINED" param
      | CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED param ->
          p_data (Unsigned.ULong.to_string ul) param

  let pack_of_yojson json : (pack , string) Result.result =
    let parse name param : (pack , string) Result.result =
      let parse_using f typ' =
        let open Ppx_deriving_yojson_runtime in
        f param >>= fun r ->
        Result.Ok (Pack (typ', r))
      in
      let p_object_class = parse_using Object_class.of_yojson in
      let p_bool = parse_using (function
          | `Bool b -> Result.Ok b
          | `String "CK_TRUE" -> Result.Ok true
          | `String "CK_FALSE" -> Result.Ok false
          | _ -> Result.Error "Not a CK_BBOOL"
        ) in
      let p_string = parse_using string_of_yojson in
      let p_data = parse_using Data.of_yojson in
      let p_key_type = parse_using Key_type.of_yojson in
      let p_ulong = parse_using ulong_of_yojson in
      let p_bigint = parse_using Pkcs11.CK_BIGINT.of_yojson in
      let p_mechanism_type = parse_using Key_gen_mechanism.of_yojson in
      let p_ec_params = parse_using Key_parsers.Asn1.EC.Params.of_yojson in
      let p_ec_point = parse_using (fun js ->
          let open Ppx_deriving_yojson_runtime in
          Data.of_yojson js >|= Cstruct.of_string
        )
      in
      let p_not_implemented typ' =
        let open Ppx_deriving_yojson_runtime in
        Data.of_yojson param >>= fun p ->
        Result.Ok (Pack (typ', Attribute_type.NOT_IMPLEMENTED p))
      in
      let open Attribute_type in
      match name with
        | "CKA_CLASS" ->
            p_object_class CKA_CLASS
        | "CKA_TOKEN" ->
            p_bool CKA_TOKEN
        | "CKA_PRIVATE" ->
            p_bool CKA_PRIVATE
        | "CKA_LABEL" ->
            p_string CKA_LABEL
        | "CKA_VALUE" ->
            p_data CKA_VALUE
        | "CKA_TRUSTED" ->
            p_bool CKA_TRUSTED
        | "CKA_KEY_TYPE" ->
            p_key_type CKA_KEY_TYPE
        | "CKA_SUBJECT" ->
            p_string CKA_SUBJECT
        | "CKA_ID" ->
            p_string CKA_ID
        | "CKA_SENSITIVE" ->
            p_bool CKA_SENSITIVE
        | "CKA_ENCRYPT" ->
            p_bool CKA_ENCRYPT
        | "CKA_DECRYPT" ->
            p_bool CKA_DECRYPT
        | "CKA_WRAP" ->
            p_bool CKA_WRAP
        | "CKA_UNWRAP" ->
            p_bool CKA_UNWRAP
        | "CKA_SIGN" ->
            p_bool CKA_SIGN
        | "CKA_SIGN_RECOVER" ->
            p_bool CKA_SIGN_RECOVER
        | "CKA_VERIFY" ->
            p_bool CKA_VERIFY
        | "CKA_VERIFY_RECOVER" ->
            p_bool CKA_VERIFY_RECOVER
        | "CKA_DERIVE" ->
            p_bool CKA_DERIVE
        | "CKA_MODULUS" ->
            p_bigint CKA_MODULUS
        | "CKA_MODULUS_BITS" ->
            p_ulong CKA_MODULUS_BITS
        | "CKA_PUBLIC_EXPONENT" ->
            p_bigint CKA_PUBLIC_EXPONENT
        | "CKA_PRIVATE_EXPONENT" ->
            p_bigint CKA_PRIVATE_EXPONENT
        | "CKA_PRIME_1" ->
            p_bigint CKA_PRIME_1
        | "CKA_PRIME_2" ->
            p_bigint CKA_PRIME_2
        | "CKA_EXPONENT_1" ->
            p_bigint CKA_EXPONENT_1
        | "CKA_EXPONENT_2" ->
            p_bigint CKA_EXPONENT_2
        | "CKA_COEFFICIENT" ->
            p_bigint CKA_COEFFICIENT
        | "CKA_PRIME" ->
            p_bigint CKA_PRIME
        | "CKA_SUBPRIME" ->
            p_bigint CKA_SUBPRIME
        | "CKA_VALUE_LEN" ->
            p_ulong CKA_VALUE_LEN
        | "CKA_EXTRACTABLE" ->
            p_bool CKA_EXTRACTABLE
        | "CKA_LOCAL" ->
            p_bool CKA_LOCAL
        | "CKA_NEVER_EXTRACTABLE" ->
            p_bool CKA_NEVER_EXTRACTABLE
        | "CKA_ALWAYS_SENSITIVE" ->
            p_bool CKA_ALWAYS_SENSITIVE
        | "CKA_KEY_GEN_MECHANISM" ->
            p_mechanism_type CKA_KEY_GEN_MECHANISM
        | "CKA_MODIFIABLE" ->
            p_bool CKA_MODIFIABLE
        (* | "CKA_ECDSA_PARAMS" -> *)
        (*     p_data CKA_ECDSA_PARAMS *)
        | "CKA_EC_PARAMS" ->
            p_ec_params CKA_EC_PARAMS
        | "CKA_EC_POINT" ->
            p_ec_point CKA_EC_POINT
        | "CKA_ALWAYS_AUTHENTICATE" ->
            p_bool CKA_ALWAYS_AUTHENTICATE
        | "CKA_WRAP_WITH_TRUSTED" ->
            p_bool CKA_WRAP_WITH_TRUSTED
        | "CKA_APPLICATION" ->
            p_not_implemented CKA_APPLICATION
        | "CKA_OBJECT_ID" ->
            p_not_implemented CKA_OBJECT_ID
        | "CKA_CERTIFICATE_TYPE" ->
            p_not_implemented CKA_CERTIFICATE_TYPE
        | "CKA_ISSUER" ->
            p_not_implemented CKA_ISSUER
        | "CKA_SERIAL_NUMBER" ->
            p_not_implemented CKA_SERIAL_NUMBER
        | "CKA_AC_ISSUER" ->
            p_not_implemented CKA_AC_ISSUER
        | "CKA_OWNER" ->
            p_not_implemented CKA_OWNER
        | "CKA_ATTR_TYPES" ->
            p_not_implemented CKA_ATTR_TYPES
        | "CKA_CERTIFICATE_CATEGORY" ->
            p_not_implemented CKA_CERTIFICATE_CATEGORY
        | "CKA_JAVA_MIDP_SECURITY_DOMAIN" ->
            p_not_implemented CKA_JAVA_MIDP_SECURITY_DOMAIN
        | "CKA_URL" ->
            p_not_implemented CKA_URL
        | "CKA_HASH_OF_SUBJECT_PUBLIC_KEY" ->
            p_not_implemented CKA_HASH_OF_SUBJECT_PUBLIC_KEY
        | "CKA_HASH_OF_ISSUER_PUBLIC_KEY" ->
            p_not_implemented CKA_HASH_OF_ISSUER_PUBLIC_KEY
        | "CKA_CHECK_VALUE" ->
            p_not_implemented CKA_CHECK_VALUE
        | "CKA_START_DATE" ->
            p_not_implemented CKA_START_DATE
        | "CKA_END_DATE" ->
            p_not_implemented CKA_END_DATE
        | "CKA_BASE" ->
            p_not_implemented CKA_BASE
        | "CKA_PRIME_BITS" ->
            p_ulong CKA_PRIME_BITS
        | "CKA_SUBPRIME_BITS" ->
            p_ulong CKA_SUBPRIME_BITS
        | "CKA_VALUE_BITS" ->
            p_not_implemented CKA_VALUE_BITS
        | "CKA_SECONDARY_AUTH" ->
            p_not_implemented CKA_SECONDARY_AUTH
        | "CKA_AUTH_PIN_FLAGS" ->
            p_not_implemented CKA_AUTH_PIN_FLAGS
        | "CKA_WRAP_TEMPLATE" ->
            p_not_implemented CKA_WRAP_TEMPLATE
        | "CKA_UNWRAP_TEMPLATE" ->
            p_not_implemented CKA_UNWRAP_TEMPLATE
        | "CKA_OTP_FORMAT" ->
            p_not_implemented CKA_OTP_FORMAT
        | "CKA_OTP_LENGTH" ->
            p_not_implemented CKA_OTP_LENGTH
        | "CKA_OTP_TIME_INTERVAL" ->
            p_not_implemented CKA_OTP_TIME_INTERVAL
        | "CKA_OTP_USER_FRIENDLY_MODE" ->
            p_not_implemented CKA_OTP_USER_FRIENDLY_MODE
        | "CKA_OTP_CHALLENGE_REQUIREMENT" ->
            p_not_implemented CKA_OTP_CHALLENGE_REQUIREMENT
        | "CKA_OTP_TIME_REQUIREMENT" ->
            p_not_implemented CKA_OTP_TIME_REQUIREMENT
        | "CKA_OTP_COUNTER_REQUIREMENT" ->
            p_not_implemented CKA_OTP_COUNTER_REQUIREMENT
        | "CKA_OTP_PIN_REQUIREMENT" ->
            p_not_implemented CKA_OTP_PIN_REQUIREMENT
        | "CKA_OTP_COUNTER" ->
            p_not_implemented CKA_OTP_COUNTER
        | "CKA_OTP_TIME" ->
            p_not_implemented CKA_OTP_TIME
        | "CKA_OTP_USER_IDENTIFIER" ->
            p_not_implemented CKA_OTP_USER_IDENTIFIER
        | "CKA_OTP_SERVICE_IDENTIFIER" ->
            p_not_implemented CKA_OTP_SERVICE_IDENTIFIER
        | "CKA_OTP_SERVICE_LOGO" ->
            p_not_implemented CKA_OTP_SERVICE_LOGO
        | "CKA_OTP_SERVICE_LOGO_TYPE" ->
            p_not_implemented CKA_OTP_SERVICE_LOGO_TYPE
        | "CKA_HW_FEATURE_TYPE" ->
            p_not_implemented CKA_HW_FEATURE_TYPE
        | "CKA_RESET_ON_INIT" ->
            p_not_implemented CKA_RESET_ON_INIT
        | "CKA_HAS_RESET" ->
            p_not_implemented CKA_HAS_RESET
        | "CKA_PIXEL_X" ->
            p_not_implemented CKA_PIXEL_X
        | "CKA_PIXEL_Y" ->
            p_not_implemented CKA_PIXEL_Y
        | "CKA_RESOLUTION" ->
            p_not_implemented CKA_RESOLUTION
        | "CKA_CHAR_ROWS" ->
            p_not_implemented CKA_CHAR_ROWS
        | "CKA_CHAR_COLUMNS" ->
            p_not_implemented CKA_CHAR_COLUMNS
        | "CKA_COLOR" ->
            p_not_implemented CKA_COLOR
        | "CKA_BITS_PER_PIXEL" ->
            p_not_implemented CKA_BITS_PER_PIXEL
        | "CKA_CHAR_SETS" ->
            p_not_implemented CKA_CHAR_SETS
        | "CKA_ENCODING_METHODS" ->
            p_not_implemented CKA_ENCODING_METHODS
        | "CKA_MIME_TYPES" ->
            p_not_implemented CKA_MIME_TYPES
        | "CKA_MECHANISM_TYPE" ->
            p_not_implemented CKA_MECHANISM_TYPE
        | "CKA_REQUIRED_CMS_ATTRIBUTES" ->
            p_not_implemented CKA_REQUIRED_CMS_ATTRIBUTES
        | "CKA_DEFAULT_CMS_ATTRIBUTES" ->
            p_not_implemented CKA_DEFAULT_CMS_ATTRIBUTES
        | "CKA_SUPPORTED_CMS_ATTRIBUTES" ->
            p_not_implemented CKA_SUPPORTED_CMS_ATTRIBUTES
        | "CKA_ALLOWED_MECHANISMS" ->
            p_not_implemented CKA_ALLOWED_MECHANISMS
        | "CKA_VENDOR_DEFINED" ->
            p_not_implemented CKA_VENDOR_DEFINED
        | _ as ul ->
            try
              p_not_implemented
                (CKA_CS_UNKNOWN (Unsigned.ULong.of_string ul))
            with Failure _ -> Result.Error "Invalid attribute"
    in
    match json with
      | `Assoc [ name, param ] ->
          parse name param
      | _ ->
          Result.Error "Ill-formed attribute"

  let pack_to_yojson (Pack x) = to_json x

  let compare_types = Pkcs11.CK_ATTRIBUTE.compare_types
  let compare_types_pack = Pkcs11.CK_ATTRIBUTE.compare_types_pack

  let compare = Pkcs11.CK_ATTRIBUTE.compare
  let compare_pack = Pkcs11.CK_ATTRIBUTE.compare_pack

  let equal = Pkcs11.CK_ATTRIBUTE.equal
  let equal_pack = Pkcs11.CK_ATTRIBUTE.equal_pack
  let equal_types_pack a b = (compare_types_pack a b) = 0
  let equal_values a v1 v2 = equal (a,v1) (a,v2)

  type kind =
    | Secret (* Can be used by secret keys. *)
    | Public (* Can be used by public keys. *)
    | Private (* Can be used by private keys. *)
    | RSA (* Can ONLY be used by RSA keys. *)
    | EC (* Can ONLY be used by elliptic curves keys. *)

  (* [kinds] returns a list of list.

     An attribute has kinds [ A; B; C ] if one of the lists returned by
     [kinds] has at least kinds [ A; B; C ]. *)
  let kinds : pack -> _ = fun (Pack (a,_)) ->
    let open Attribute_type in
    let secret_public_private = [ [ Secret; Public; Private ] ] in
    let secret_public = [ [ Secret; Public ] ] in
    let secret_private = [ [ Secret; Private ] ] in
    let rsa_private = [ [ RSA; Private ] ] in
    match a with
      (* Common Object Attributes *)
      | CKA_CLASS -> secret_public_private
      (* Common Storage Object Attributes *)
      | CKA_TOKEN      -> secret_public_private
      | CKA_PRIVATE    -> secret_public_private
      | CKA_MODIFIABLE -> secret_public_private
      | CKA_LABEL      -> secret_public_private
      (* Common Key Attributes *)
      | CKA_KEY_TYPE          -> secret_public_private
      | CKA_ID                -> secret_public_private
      | CKA_DERIVE            -> secret_public_private
      | CKA_LOCAL             -> secret_public_private
      | CKA_KEY_GEN_MECHANISM -> secret_public_private
      (* Public and Secret Key Attributes *)
      | CKA_ENCRYPT        -> secret_public
      | CKA_VERIFY         -> secret_public
      | CKA_VERIFY_RECOVER -> secret_public
      | CKA_WRAP           -> secret_public
      | CKA_TRUSTED        -> secret_public
      (* Private and Secret Key Attributes *)
      | CKA_SENSITIVE           -> secret_private
      | CKA_DECRYPT             -> secret_private
      | CKA_SIGN                -> secret_private
      | CKA_SIGN_RECOVER        -> secret_private
      | CKA_UNWRAP              -> secret_private
      | CKA_EXTRACTABLE         -> secret_private
      | CKA_ALWAYS_SENSITIVE    -> secret_private
      | CKA_NEVER_EXTRACTABLE   -> secret_private
      | CKA_WRAP_WITH_TRUSTED   -> secret_private
      | CKA_ALWAYS_AUTHENTICATE -> secret_private
      (* Mechanism-Specific *)
      | CKA_VALUE            -> [ [ Secret ]; [ EC; Private ] ]
      | CKA_VALUE_LEN        -> [ [ Secret ] ]
      | CKA_MODULUS          -> [ [ RSA; Public; Private ] ]
      | CKA_PUBLIC_EXPONENT  -> [ [ RSA; Public; Private ] ]
      | CKA_MODULUS_BITS     -> [ [ RSA; Public ] ]
      | CKA_PRIVATE_EXPONENT -> rsa_private
      | CKA_PRIME_1          -> rsa_private
      | CKA_PRIME_2          -> rsa_private
      | CKA_EXPONENT_1       -> rsa_private
      | CKA_EXPONENT_2       -> rsa_private
      | CKA_COEFFICIENT      -> rsa_private
      | CKA_PRIME            -> []
      | CKA_SUBPRIME         -> []
      (* | CKA_ECDSA_PARAMS     -> [ [ EC; Public; Private ] ] *)
      | CKA_EC_PARAMS        -> [ [ EC; Public; Private ] ]
      | CKA_EC_POINT         -> [ [ EC; Public ] ]
      | CKA_SUBJECT          -> [ [ Public; Private ] ]
      | CKA_APPLICATION -> assert false
      | CKA_OBJECT_ID -> assert false
      | CKA_CERTIFICATE_TYPE -> assert false
      | CKA_ISSUER -> assert false
      | CKA_SERIAL_NUMBER -> assert false
      | CKA_AC_ISSUER -> assert false
      | CKA_OWNER -> assert false
      | CKA_ATTR_TYPES -> assert false
      | CKA_CERTIFICATE_CATEGORY -> assert false
      | CKA_JAVA_MIDP_SECURITY_DOMAIN -> assert false
      | CKA_URL -> assert false
      | CKA_HASH_OF_SUBJECT_PUBLIC_KEY -> assert false
      | CKA_HASH_OF_ISSUER_PUBLIC_KEY -> assert false
      | CKA_CHECK_VALUE -> assert false
      | CKA_START_DATE -> assert false
      | CKA_END_DATE -> assert false
      | CKA_BASE -> assert false
      | CKA_PRIME_BITS -> assert false
      | CKA_SUBPRIME_BITS -> assert false
      (* | CKA_SUB_PRIME_BITS -> assert false *)
      | CKA_VALUE_BITS -> assert false
      | CKA_SECONDARY_AUTH -> assert false
      | CKA_AUTH_PIN_FLAGS -> assert false
      | CKA_WRAP_TEMPLATE -> assert false
      | CKA_UNWRAP_TEMPLATE -> assert false
      | CKA_OTP_FORMAT -> assert false
      | CKA_OTP_LENGTH -> assert false
      | CKA_OTP_TIME_INTERVAL -> assert false
      | CKA_OTP_USER_FRIENDLY_MODE -> assert false
      | CKA_OTP_CHALLENGE_REQUIREMENT -> assert false
      | CKA_OTP_TIME_REQUIREMENT -> assert false
      | CKA_OTP_COUNTER_REQUIREMENT -> assert false
      | CKA_OTP_PIN_REQUIREMENT -> assert false
      | CKA_OTP_COUNTER -> assert false
      | CKA_OTP_TIME -> assert false
      | CKA_OTP_USER_IDENTIFIER -> assert false
      | CKA_OTP_SERVICE_IDENTIFIER -> assert false
      | CKA_OTP_SERVICE_LOGO -> assert false
      | CKA_OTP_SERVICE_LOGO_TYPE -> assert false
      | CKA_HW_FEATURE_TYPE -> assert false
      | CKA_RESET_ON_INIT -> assert false
      | CKA_HAS_RESET -> assert false
      | CKA_PIXEL_X -> assert false
      | CKA_PIXEL_Y -> assert false
      | CKA_RESOLUTION -> assert false
      | CKA_CHAR_ROWS -> assert false
      | CKA_CHAR_COLUMNS -> assert false
      | CKA_COLOR -> assert false
      | CKA_BITS_PER_PIXEL -> assert false
      | CKA_CHAR_SETS -> assert false
      | CKA_ENCODING_METHODS -> assert false
      | CKA_MIME_TYPES -> assert false
      | CKA_MECHANISM_TYPE -> assert false
      | CKA_REQUIRED_CMS_ATTRIBUTES -> assert false
      | CKA_DEFAULT_CMS_ATTRIBUTES -> assert false
      | CKA_SUPPORTED_CMS_ATTRIBUTES -> assert false
      | CKA_ALLOWED_MECHANISMS -> assert false
      | CKA_VENDOR_DEFINED -> assert false
      | CKA_CS_UNKNOWN _ -> []

  (* Return whether [a] has all kinds [k]. *)
  let is (k: kind list) (a: pack) =
    List.exists
      (fun kinds -> List.for_all (fun k -> List.mem k kinds) k)
      (kinds a)

  let type_ (Pack (ty,_)) = Attribute_type.Pack ty

  let equal_kind (x:kind) y =
    x = y

end

module Attribute_types =
struct
  type t = Attribute_type.pack list [@@deriving yojson]
  let rec mem: type a . t -> a Attribute_type.t -> bool = fun template x ->
    match template with
      | [] -> false
      | head :: tail ->
          match head with
            | Attribute_type.Pack ty ->
                match Pkcs11.CK_ATTRIBUTE_TYPE.compare' ty x with
                  | Pkcs11.CK_ATTRIBUTE_TYPE.Equal -> true
                  | Pkcs11.CK_ATTRIBUTE_TYPE.Not_equal _ -> mem tail x

  let rec remove_duplicates l acc =
    match l with
      | [] -> List.rev acc
      | (Attribute_type.Pack ty as p)::q ->
          if mem acc ty
          then remove_duplicates q acc
          else remove_duplicates q (p::acc)

  (** compares two normalized types list  *)
  let rec compare a b =
    match a,b with
      | [], [] -> 0
      | [], _::_ -> -1
      | _::_, [] -> 1
      | a1::a2, b1::b2 ->
          let cmp = Attribute_type.compare_pack a1 b1 in
          if cmp = 0
          then compare a2 b2
          else cmp

  let remove_duplicates l = remove_duplicates l []

  let typ =
    Record.Type.make
      ~name: "attribute_type_list"
      ~to_yojson
      ~of_yojson
      ()
end

module Template =
struct
  type t = Attribute.pack list

  let to_yojson template :Yojson.Safe.json =
    let attributes = List.map (fun (Attribute.Pack x) -> Attribute.to_json x) template in
    let flatten_attribute = function
      | `Assoc l -> l
      | _ -> assert false (* All attributes are represented using [`Assoc]. *)
    in
    let attributes = List.map flatten_attribute attributes |> List.flatten in
    `Assoc attributes

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    match json with
      | `Assoc assoc ->
          begin
            let attributes = List.map (fun (a, b) -> `Assoc [ a, b ]) assoc in
            map_bind Attribute.pack_of_yojson [] attributes
          end
      | _ -> Result.Error "Ill-formed template"

  let typ =
    Record.Type.make
      ~name: "template"
      ~to_yojson
      ~of_yojson
      ()

  let rec get : type a . t -> a Attribute_type.t -> a option = fun template x ->
    match template with
      | [] -> None
      | head :: tail ->
          match head with
            | Attribute.Pack (ty,v) ->
                match Pkcs11.CK_ATTRIBUTE_TYPE.compare' ty x with
                  | Pkcs11.CK_ATTRIBUTE_TYPE.Equal -> Some v
                  | Pkcs11.CK_ATTRIBUTE_TYPE.Not_equal _ -> get tail x

  let get_pack template (Attribute_type.Pack ty) =
    match get template ty with
      | None -> None
      | Some v -> Some (Attribute.Pack (ty,v))

  let of_raw = Pkcs11.Template.view

  (** [normalize t] returns a normal form for the template [t]. That
      is, a template that is sorted. *)
  let normalize (t:t) : t =
    List.sort Attribute.compare_pack t

  (** compares two normalized templates  *)
  let rec compare a b =
    match a,b with
      | [], [] -> 0
      | [], _::_ -> -1
      | _::_, [] -> 1
      | a1::a2, b1::b2 ->
          let cmp = Attribute.compare_pack a1 b1 in
          if cmp = 0
          then compare a2 b2
          else cmp

  (** safe mem on templates. *)
  let mem elem = List.exists (Attribute.equal_pack elem)

  (* Operations  *)
  let fold = List.fold_right

  (* Replace the value of [attribute] in [template] if it already
     exists.  Add [attribute] otherwise. *)
  let set_attribute attribute (template : Attribute.pack list) =
    let exists = ref false in
    let replace_value old_attribute =
      if
        Attribute.compare_types_pack old_attribute attribute = 0
      then
        (exists := true; attribute)
      else
        old_attribute
    in
    let template = List.map replace_value template in
    if !exists then
      template
    else
      attribute :: template

  let remove_attribute attribute template =
    List.filter (fun x -> not (Attribute.equal_pack x attribute)) template

  let remove_attribute_type attribute_type template =
    List.filter (fun x ->
        let x = Attribute.type_ x in
        not (Attribute_type.equal_pack x attribute_type)) template

  let attribute_types template =
    List.map Attribute.type_ template

  let union template1 template2 =
    List.fold_left
      (fun template attribute -> set_attribute attribute template)
      template2
      (List.rev template1)

  let only_attribute_types types template =
    List.fold_left (fun template attribute ->
        let type_ = Attribute.type_ attribute in
        if List.exists (Attribute_type.equal_pack type_) types
        then attribute::template
        else template
      ) [] template
    |> List.rev

  let except_attribute_types types template =
    List.fold_left (fun template attribute ->
        let type_ = Attribute.type_ attribute in
        if List.exists (Attribute_type.equal_pack type_) types
        then template
        else attribute:: template
      ) [] template
    |> List.rev

  let find_attribute_types types template =
    let rec aux types result =
      match types with
        | [] -> Some (List.rev result)
        | ty::q ->
            begin match get_pack template ty with
              | None -> None
              | Some a -> aux q (a::result)
            end
    in
    aux types []

  let correspond ~source ~tested =
    (* For all the elements of source, check if an element in tested
       correspond. *)
    List.for_all
      (fun x -> List.exists (Attribute.equal_pack x) tested)
      source

  (** For all the elements of source, check if an element in tested
      correspond. Return a tuple with the list of elements from source
      which are expected but not found in tested and a list of elements
      which are found but with a different value.
  *)
  let diff ~source ~tested =
    let empty = ([], []) in
    List.fold_left (
      fun
        (missing, different)
        (Attribute.Pack (attribute, a_value) as pack) ->
        match get tested attribute with
          | None ->
              let missing = pack :: missing in
              missing, different
          | Some value ->
              let different =
                if a_value = value then
                  different
                else
                  pack :: different
              in
              missing, different
    ) empty source

  let to_string t =
    to_yojson t |> Yojson.Safe.to_string

  let pp fmt t = Format.fprintf fmt "%s" @@ to_string t

  let hash t =
    normalize t |> to_string |> Digest.string

  let get_class t = get t Attribute_type.CKA_CLASS
  let get_key_type t = get t Attribute_type.CKA_KEY_TYPE
  let get_label t = get t Attribute_type.CKA_LABEL
end

(******************************************************************************)
(*                                  Commands                                  *)
(******************************************************************************)

exception CKR of RV.t

let () =
  Printexc.register_printer
    begin function
      | CKR s -> Some (RV.to_string s)
      | _ -> None
    end

module type S =
sig
  val initialize : unit -> unit
  val finalize : unit -> unit
  val get_info : unit -> Info.t
  val get_slot : Slot.t -> (Slot_id.t, string) Result.result
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

module Make (X: Pkcs11.RAW) =
struct

  module Low_level = X
  module Intermediate_level = Pkcs11.Make(X)
  include Intermediate_level

  type 'a t = 'a
  let return x = x
  let (>>=) x f = f x

  let check_ckr rv x =
    let rv = Pkcs11.CK_RV.view rv in
    if RV.equal rv RV.CKR_OK
    then x
    else raise (CKR rv)

  let check_ckr_unit rv =
    let rv = Pkcs11.CK_RV.view rv in
    if not (RV.equal rv RV.CKR_OK)
    then raise (CKR rv)

  let (>>?) rv f =
    let rv = Pkcs11.CK_RV.view rv in
    if RV.equal rv RV.CKR_OK
    then f ()
    else raise (CKR rv)

  let initialize : unit -> unit t = fun () ->
    let rv = c_Initialize () in
    check_ckr_unit rv

  let finalize : unit -> unit t = fun () ->
    let rv = c_Finalize () in
    check_ckr_unit rv

  let get_info : unit -> Info.t t = fun () ->
    let rv,info= c_GetInfo () in
    check_ckr rv info

  let get_slot_list : bool -> Slot_id.t list t = fun token_present ->
    let slot_list = Pkcs11.Slot_list.create () in
    c_GetSlotList token_present slot_list >>? fun () ->
    Pkcs11.Slot_list.allocate slot_list;
    c_GetSlotList token_present slot_list >>? fun () ->
    return (Pkcs11.Slot_list.view slot_list)

  let get_slot_info : slot: Slot_id.t -> Slot_info.t t = fun ~slot ->
    let rv, info = c_GetSlotInfo ~slot in
    check_ckr rv info

  let get_token_info: slot: Slot_id.t -> Token_info.t t = fun ~slot ->
    let rv, info = c_GetTokenInfo ~slot in
    check_ckr rv info

  let findi_option p l =
    let rec go i = function
      | [] -> None
      | x::_ when p i x -> Some x
      | _::xs -> go (i+1) xs
    in
    go 0 l

  let trimmed_eq a b =
    let open Ctypes_helpers in
    trim_and_quote a = trim_and_quote b

  let find_slot slot_desc i slot =
    let open Slot in
    match slot_desc with
    | Id id ->
      Slot_id.equal slot @@ Unsigned.ULong.of_int id
    | Index idx ->
      idx = i
    | Description s ->
      let { Slot_info.slotDescription } = get_slot_info ~slot in
      trimmed_eq slotDescription s
    | Label s ->
      let { Token_info.label } = get_token_info ~slot in
      trimmed_eq label s

  let get_slot slot =
    let open Slot in
    let slot_list = get_slot_list false in
    let predicate = find_slot slot in
    match findi_option predicate slot_list with
    | Some s -> Result.Ok s
    | None -> Result.Error (invalid_slot_msg slot)

  let get_mechanism_list: slot: Slot_id.t -> Mechanism_type.t list t =
    fun ~slot ->
      let l = Pkcs11.Mechanism_list.create () in
      c_GetMechanismList ~slot l >>? fun () ->
      Pkcs11.Mechanism_list.allocate l;
      c_GetMechanismList ~slot l >>? fun () ->
      return (Pkcs11.Mechanism_list.view l)

  let get_mechanism_info : slot: Slot_id.t -> Mechanism_type.t ->
    Mechanism_info.t t =
    fun ~slot mech ->
      let rv,info = c_GetMechanismInfo ~slot (Pkcs11.CK_MECHANISM_TYPE.make mech) in
      check_ckr rv info

  let init_token : slot: Slot_id.t -> pin: string -> label: string -> unit t =
    fun ~slot ~pin ~label ->
      check_ckr_unit (c_InitToken ~slot ~pin ~label)

  let init_PIN : Session_handle.t -> pin: string -> unit t =
    fun hSession ~pin ->
    check_ckr_unit (c_InitPIN hSession pin)

  let set_PIN : Session_handle.t -> oldpin: string -> newpin: string -> unit t =
    fun hSession ~oldpin ~newpin ->
      check_ckr_unit (c_SetPIN hSession ~oldpin ~newpin)

  let open_session: slot: Slot_id.t -> flags: Flags.t -> Session_handle.t t =
    fun ~slot ~flags ->
      let rv, hs = c_OpenSession ~slot ~flags in
      check_ckr rv hs

  let close_session: Session_handle.t -> unit t =
    fun hSession ->
      check_ckr_unit (c_CloseSession hSession)

  let close_all_sessions: slot: Slot_id.t -> unit t=
    fun ~slot ->
      check_ckr_unit (c_CloseAllSessions ~slot)

  let get_session_info : Session_handle.t -> Session_info.t t =
    fun hSession ->
      let rv, info = c_GetSessionInfo hSession in
      check_ckr rv info

  let login : Session_handle.t -> User_type.t -> string -> unit t =
    fun hSession usertype pin ->
      let usertype = Pkcs11.CK_USER_TYPE.make usertype in
      check_ckr_unit (c_Login hSession usertype pin)

  let logout : Session_handle.t -> unit t =
    fun hSession ->
      check_ckr_unit (c_Logout hSession)

  let create_object: Session_handle.t -> Template.t -> Object_handle.t t =
    fun hSession template ->
      let rv, hObj = c_CreateObject hSession (Pkcs11.Template.make template) in
      check_ckr rv hObj

  let copy_object: Session_handle.t -> Object_handle.t -> Template.t ->
    Object_handle.t t =
    fun hSession hObj template ->
      let rv, hObj' =
        c_CopyObject hSession hObj (Pkcs11.Template.make template)
      in
      check_ckr rv hObj'

  let destroy_object: Session_handle.t -> Object_handle.t -> unit t =
    fun hSession hObj ->
    check_ckr_unit (c_DestroyObject hSession hObj)

  let get_attribute_value
        hSession
        (hObject: Object_handle.t)
        (query: Attribute_types.t)
    : Template.t t =
    let query = List.map (fun (Attribute_type.Pack x) ->
        Pkcs11.CK_ATTRIBUTE.create (
          Pkcs11.CK_ATTRIBUTE_TYPE.make x)) query in
    let query: Pkcs11.Template.t = Pkcs11.Template.of_list query in
    c_GetAttributeValue hSession hObject query >>? fun () ->
    Pkcs11.Template.allocate query;
    c_GetAttributeValue hSession hObject query >>? fun () ->
    return (Pkcs11.Template.view query)

  let get_attribute_value' hSession hObject query : Template.t t =
    List.fold_left (fun acc attribute ->
        try
          let attr = get_attribute_value hSession hObject [attribute] in
          attr @ acc
        with CKR _ -> acc
      ) [] query
    |> List.rev
    |> return


    module CKA_map = Map.Make(struct
      type t = Attribute_type.pack
      let compare = Attribute_type.compare_pack
    end)
  let get_attribute_value_optimized tracked_attributes =
    (* TODO: have one score table per device / per slot / per session? *)
    let results: (int * int) CKA_map.t ref = ref CKA_map.empty in
    let count = ref 0 in
    let get_results attribute_type =
      try
        CKA_map.find attribute_type !results
      with Not_found ->
        0,0
    in
    let incr_failures (attribute_type : Attribute_type.pack) =
      let successes,failures = get_results attribute_type in
      results :=
        CKA_map.add attribute_type (successes, failures + 1) !results
    in
    let incr_successes (attribute_type : Attribute_type.pack) =
      let successes,failures = get_results attribute_type in
      results :=
        CKA_map.add attribute_type (1+successes, failures) !results
    in
    let can_group attribute_type =
      (* Group only if the failure rate is less than 1%. *)
      let _, failures = get_results attribute_type in
      failures * 100 / !count < 1
    in
    `Optimized (fun session handle ->
        let rec ask_one_by_one acc attributes =
          match attributes with
            | [] ->
                acc (* Order does not matter. *)
            | head :: tail ->
                try
                  let value = get_attribute_value session handle [ head ] in
                  incr_successes head;
                  ask_one_by_one (value @ acc) tail
                with CKR _ ->
                  incr_failures head;
                  ask_one_by_one acc tail
        in
        incr count;
        let group, singles = List.partition can_group tracked_attributes in
        (* Try to ask attributes which work most of the time all at once.
           If it failed, revert to one-by-one mode. *)
        let group_template =
          try
            let r = get_attribute_value session handle group in
            List.iter incr_successes group;
            r
          with CKR _ ->
            ask_one_by_one [] group
        in
        (* Complete the template with other attributes, the ones which fail
           often and which we always ask one by one. *)
        ask_one_by_one group_template singles)

  let set_attribute_value
      hSession
      (hObject: Object_handle.t)
      (query : Attribute.pack list)
    : unit t =
    let query =
      List.map (fun (Attribute.Pack x) ->
          Pkcs11.CK_ATTRIBUTE.make x) query |> Pkcs11.Template.of_list
    in
    c_SetAttributeValue hSession hObject query >>? fun () ->
    return ()

  (* Do not call c_FindObjectFinal.  *)
  let rec find_all acc hSession ~max_size =
    let rv,l = c_FindObjects hSession ~max_size in
    check_ckr rv l >>= fun l ->
    if l <> []
    then find_all (List.rev_append l acc) hSession ~max_size
    else return @@ List.rev acc

  let find_objects:
    ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list t =
    fun ?(max_size=5) hSession template ->
      let template = Pkcs11.Template.make template in
      c_FindObjectsInit hSession template >>? fun () ->
      find_all [] hSession ~max_size >>= fun l ->
      let rv = c_FindObjectsFinal hSession in
      check_ckr_unit rv >>= fun () ->
      return l


  let encrypt hSession mech hObject plain : Data.t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_EncryptInit hSession mech hObject >>? fun () ->
    let plain = Pkcs11.Data.of_string plain in
    let cipher = Pkcs11.Data.create () in
    c_Encrypt hSession ~src:plain ~tgt:cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_Encrypt hSession ~src:plain ~tgt:cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt_init : Session_handle.t -> Mechanism.t -> Object_handle.t
    -> unit t =
    fun hSession mech hObject ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_EncryptInit hSession mech hObject >>? return

  let multipart_encrypt_chunck hSession plain : Data.t
    =
    let plain = Pkcs11.Data.of_string plain in
    let cipher = Pkcs11.Data.create () in
    c_EncryptUpdate hSession plain cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_EncryptUpdate hSession plain cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt_final : Session_handle.t ->  Data.t =
    fun hSession ->
      let cipher = Pkcs11.Data.create () in
      c_EncryptFinal hSession cipher >>? fun () ->
      let () = Pkcs11.Data.allocate cipher in
      c_EncryptFinal hSession cipher >>? fun () ->
      return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t =
    fun hSession mech hKey parts ->
      multipart_encrypt_init hSession mech hKey;
      let cipher =
        List.map
          (fun x -> multipart_encrypt_chunck hSession x)
          parts
        |> String.concat ""
      in
      let lastPart = multipart_encrypt_final hSession in
      cipher^lastPart

  let decrypt hSession mech hObject cipher : Data.t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_DecryptInit hSession mech hObject >>? fun () ->
    let cipher = Pkcs11.Data.of_string cipher in
    let plain = Pkcs11.Data.create () in
    c_Decrypt hSession ~src:cipher ~tgt:plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_Decrypt hSession ~src:cipher ~tgt:plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt_init : Session_handle.t -> Mechanism.t -> Object_handle.t
    -> unit t =
    fun hSession mech hObject ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_DecryptInit hSession mech hObject >>? return

  let multipart_decrypt_chunck hSession cipher : Data.t
    =
    let cipher = Pkcs11.Data.of_string cipher in
    let plain = Pkcs11.Data.create () in
    c_DecryptUpdate hSession cipher plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_DecryptUpdate hSession cipher plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt_final : Session_handle.t ->  Data.t =
    fun hSession ->
      let plain = Pkcs11.Data.create () in
      c_DecryptFinal hSession plain >>? fun () ->
      let () = Pkcs11.Data.allocate plain in
      c_DecryptFinal hSession plain >>? fun () ->
      return (Pkcs11.Data.to_string plain)

  let multipart_decrypt : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t =
    fun hSession mech hKey parts ->
      multipart_decrypt_init hSession mech hKey;
      let plain =
        List.map
          (fun x -> multipart_decrypt_chunck hSession x)
          parts
        |> String.concat ""
      in
      let lastPart = multipart_decrypt_final hSession in
      plain^lastPart

  let sign : Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t ->
    Data.t =
    fun hSession mech hKey plain ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_SignInit hSession mech hKey >>? fun () ->
      let plain = Pkcs11.Data.of_string plain in
      let signature = Pkcs11.Data.create () in
      c_Sign hSession ~src:plain ~tgt:signature >>? fun () ->
      let () = Pkcs11.Data.allocate signature in
      c_Sign hSession ~src:plain ~tgt:signature >>? fun () ->
      return (Pkcs11.Data.to_string signature)

  let sign_recover:
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t =
    fun hSession mech hKey plain ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_SignRecoverInit hSession mech hKey >>? fun () ->
      let plain = Pkcs11.Data.of_string plain in
      let signature = Pkcs11.Data.create () in
      c_SignRecover hSession ~src:plain ~tgt:signature >>? fun () ->
      let () = Pkcs11.Data.allocate signature in
      c_SignRecover hSession ~src:plain ~tgt:signature >>? fun () ->
      return (Pkcs11.Data.to_string signature)

  let multipart_sign_init : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    unit t =
    fun hSession mech hKey ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_SignInit hSession mech hKey >>? return

  let multipart_sign_chunck : Session_handle.t -> Data.t -> unit t =
    fun hSession part ->
      let part = Pkcs11.Data.of_string part in
      c_SignUpdate hSession part >>? return

  let multipart_sign_final : Session_handle.t -> Data.t =
    fun hSession ->
      let signature = Pkcs11.Data.create () in
      c_SignFinal hSession signature >>? fun () ->
      let () = Pkcs11.Data.allocate signature in
      c_SignFinal hSession signature >>? fun () ->
      return (Pkcs11.Data.to_string signature)

  let multipart_sign : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t =
    fun hSession mech hKey parts ->
      multipart_sign_init hSession mech hKey >>= fun () ->
      List.iter (multipart_sign_chunck hSession) parts >>= fun () ->
      multipart_sign_final hSession

  let verify:
    Session_handle.t -> Mechanism.t -> Object_handle.t ->
    data: Data.t -> signature: Data.t -> unit t =
    fun hSession mech hKey ~data ~signature ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_VerifyInit hSession mech hKey >>? fun () ->
      let signed = Pkcs11.Data.of_string data in
      let signature = Pkcs11.Data.of_string signature in
      c_Verify hSession ~signed ~signature >>? fun () ->
      return ()

  let verify_recover:
    Session_handle.t -> Mechanism.t -> Object_handle.t -> signature: string ->
    Data.t =
    fun hSession mech hKey ~signature ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_VerifyRecoverInit hSession mech hKey >>? fun () ->
      let signature = Pkcs11.Data.of_string signature in
      let signed = Pkcs11.Data.create () in
      c_VerifyRecover hSession ~signature ~signed >>? fun () ->
      let () = Pkcs11.Data.allocate signed in
      c_VerifyRecover hSession ~signature ~signed >>? fun () ->
      return (Pkcs11.Data.to_string signed)

  let multipart_verify_init:
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit t =
    fun hSession mech hKey ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_VerifyInit hSession mech hKey >>? return

  let multipart_verify_chunck: Session_handle.t -> Data.t -> unit
    =
    fun hSession part ->
      let part = Pkcs11.Data.of_string part in
      c_VerifyUpdate hSession part >>? return

  let multipart_verify_final : Session_handle.t -> Data.t -> unit t=
    fun hSession signature ->
      let signature = Pkcs11.Data.of_string signature in
      c_VerifyFinal hSession signature >>? return

  let multipart_verify : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t -> unit t =
    fun hSession mech hKey parts signature ->
      multipart_verify_init hSession mech hKey >>= fun () ->
      List.iter (multipart_verify_chunck hSession) parts >>= fun () ->
      multipart_verify_final hSession signature

  let generate_key: Session_handle.t -> Mechanism.t -> Template.t ->
    Object_handle.t t =
    fun hSession mech template ->
      let template = Pkcs11.Template.make template in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv, obj = c_GenerateKey hSession mech template in
      check_ckr rv obj

  (* returns [public,private] *)
  let generate_key_pair:
    Session_handle.t -> Mechanism.t -> Template.t ->Template.t ->
    (Object_handle.t * Object_handle.t) t =
    fun hSession mech public privat  ->
      let public = Pkcs11.Template.make public in
      let privat = Pkcs11.Template.make privat in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv, pub, priv = c_GenerateKeyPair hSession mech ~public ~privat in
      check_ckr rv (pub,priv)

  let wrap_key hSession mech wrapping_key (key: Object_handle.t):
    string t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let wrapped_key = Pkcs11.Data.create () in
    c_WrapKey hSession mech ~wrapping_key ~key ~wrapped_key >>? fun () ->
    let () = Pkcs11.Data.allocate wrapped_key in
    c_WrapKey hSession mech ~wrapping_key ~key ~wrapped_key >>? fun () ->
    return (Pkcs11.Data.to_string wrapped_key)

  let unwrap_key :
    Session_handle.t ->
    Mechanism.t ->
    Object_handle.t ->
    string ->
    Template.t ->
    Object_handle.t t =
    fun hSession mech unwrapping_key wrapped_key template ->
      let wrapped_key = Pkcs11.Data.of_string wrapped_key in
      let template = Pkcs11.Template.make template in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv,obj =
        c_UnwrapKey hSession mech ~unwrapping_key ~wrapped_key template
      in
      check_ckr rv obj

  let derive_key :
    Session_handle.t ->
    Mechanism.t ->
    Object_handle.t ->
    Template.t ->
    Object_handle.t t =
    fun hSession mech obj template ->
      let template = Pkcs11.Template.make template in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv,obj' = c_DeriveKey hSession mech obj template in
      check_ckr rv obj'

end

let load_driver ?log_calls ?on_unknown ~dll ~use_get_function_list =
  let module Implem =
    (val (Pkcs11.load_driver ?log_calls ?on_unknown ~dll ~use_get_function_list) : Pkcs11.RAW)
  in
  (module (Make (Implem)): S)
