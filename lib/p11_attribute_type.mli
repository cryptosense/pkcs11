type not_implemented = NOT_IMPLEMENTED of string

type 'a t =
  | CKA_CLASS : P11_object_class.t t
  | CKA_TOKEN : bool t
  | CKA_PRIVATE : bool t
  | CKA_LABEL : string t
  | CKA_VALUE : string t
  | CKA_TRUSTED : bool t
  | CKA_CHECK_VALUE : not_implemented t
  | CKA_KEY_TYPE : P11_key_type.t t
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
  | CKA_MODULUS : P11_bigint.t t
  | CKA_MODULUS_BITS : P11_ulong.t t
  | CKA_PUBLIC_EXPONENT : P11_bigint.t t
  | CKA_PRIVATE_EXPONENT : P11_bigint.t t
  | CKA_PRIME_1 : P11_bigint.t t
  | CKA_PRIME_2 : P11_bigint.t t
  | CKA_EXPONENT_1 : P11_bigint.t t
  | CKA_EXPONENT_2 : P11_bigint.t t
  | CKA_COEFFICIENT : P11_bigint.t t
  | CKA_PRIME : P11_bigint.t t
  | CKA_SUBPRIME : P11_bigint.t t
  | CKA_BASE : P11_bigint.t t
  | CKA_PRIME_BITS : P11_ulong.t t
  | CKA_SUBPRIME_BITS : P11_ulong.t t
  | CKA_VALUE_LEN : P11_ulong.t t
  | CKA_EXTRACTABLE : bool t
  | CKA_LOCAL : bool t
  | CKA_NEVER_EXTRACTABLE : bool t
  | CKA_ALWAYS_SENSITIVE : bool t
  | CKA_KEY_GEN_MECHANISM : P11_key_gen_mechanism.t t
  | CKA_MODIFIABLE : bool t
  | CKA_EC_PARAMS : string t
  | CKA_EC_POINT : string t
  | CKA_ALWAYS_AUTHENTICATE : bool t
  | CKA_WRAP_WITH_TRUSTED : bool t
  | CKA_WRAP_TEMPLATE : not_implemented t
  | CKA_UNWRAP_TEMPLATE : not_implemented t
  | CKA_ALLOWED_MECHANISMS : not_implemented t
  | CKA_CS_UNKNOWN : Unsigned.ULong.t -> not_implemented t

module Encoding : sig
  val _CKA_CLASS : Unsigned.ULong.t

  val _CKA_TOKEN : Unsigned.ULong.t

  val _CKA_PRIVATE : Unsigned.ULong.t

  val _CKA_LABEL : Unsigned.ULong.t

  val _CKA_APPLICATION : Unsigned.ULong.t

  val _CKA_VALUE : Unsigned.ULong.t

  val _CKA_OBJECT_ID : Unsigned.ULong.t

  val _CKA_CERTIFICATE_TYPE : Unsigned.ULong.t

  val _CKA_ISSUER : Unsigned.ULong.t

  val _CKA_SERIAL_NUMBER : Unsigned.ULong.t

  val _CKA_AC_ISSUER : Unsigned.ULong.t

  val _CKA_OWNER : Unsigned.ULong.t

  val _CKA_ATTR_TYPES : Unsigned.ULong.t

  val _CKA_TRUSTED : Unsigned.ULong.t

  val _CKA_CERTIFICATE_CATEGORY : Unsigned.ULong.t

  val _CKA_JAVA_MIDP_SECURITY_DOMAIN : Unsigned.ULong.t

  val _CKA_URL : Unsigned.ULong.t

  val _CKA_HASH_OF_SUBJECT_PUBLIC_KEY : Unsigned.ULong.t

  val _CKA_HASH_OF_ISSUER_PUBLIC_KEY : Unsigned.ULong.t

  val _CKA_CHECK_VALUE : Unsigned.ULong.t

  val _CKA_KEY_TYPE : Unsigned.ULong.t

  val _CKA_SUBJECT : Unsigned.ULong.t

  val _CKA_ID : Unsigned.ULong.t

  val _CKA_SENSITIVE : Unsigned.ULong.t

  val _CKA_ENCRYPT : Unsigned.ULong.t

  val _CKA_DECRYPT : Unsigned.ULong.t

  val _CKA_WRAP : Unsigned.ULong.t

  val _CKA_UNWRAP : Unsigned.ULong.t

  val _CKA_SIGN : Unsigned.ULong.t

  val _CKA_SIGN_RECOVER : Unsigned.ULong.t

  val _CKA_VERIFY : Unsigned.ULong.t

  val _CKA_VERIFY_RECOVER : Unsigned.ULong.t

  val _CKA_DERIVE : Unsigned.ULong.t

  val _CKA_START_DATE : Unsigned.ULong.t

  val _CKA_END_DATE : Unsigned.ULong.t

  val _CKA_MODULUS : Unsigned.ULong.t

  val _CKA_MODULUS_BITS : Unsigned.ULong.t

  val _CKA_PUBLIC_EXPONENT : Unsigned.ULong.t

  val _CKA_PRIVATE_EXPONENT : Unsigned.ULong.t

  val _CKA_PRIME_1 : Unsigned.ULong.t

  val _CKA_PRIME_2 : Unsigned.ULong.t

  val _CKA_EXPONENT_1 : Unsigned.ULong.t

  val _CKA_EXPONENT_2 : Unsigned.ULong.t

  val _CKA_COEFFICIENT : Unsigned.ULong.t

  val _CKA_PRIME : Unsigned.ULong.t

  val _CKA_SUBPRIME : Unsigned.ULong.t

  val _CKA_BASE : Unsigned.ULong.t

  val _CKA_PRIME_BITS : Unsigned.ULong.t

  val _CKA_SUBPRIME_BITS : Unsigned.ULong.t

  val _CKA_VALUE_BITS : Unsigned.ULong.t

  val _CKA_VALUE_LEN : Unsigned.ULong.t

  val _CKA_EXTRACTABLE : Unsigned.ULong.t

  val _CKA_LOCAL : Unsigned.ULong.t

  val _CKA_NEVER_EXTRACTABLE : Unsigned.ULong.t

  val _CKA_ALWAYS_SENSITIVE : Unsigned.ULong.t

  val _CKA_KEY_GEN_MECHANISM : Unsigned.ULong.t

  val _CKA_MODIFIABLE : Unsigned.ULong.t

  val _CKA_EC_PARAMS : Unsigned.ULong.t

  val _CKA_EC_POINT : Unsigned.ULong.t

  val _CKA_SECONDARY_AUTH : Unsigned.ULong.t

  val _CKA_AUTH_PIN_FLAGS : Unsigned.ULong.t

  val _CKA_ALWAYS_AUTHENTICATE : Unsigned.ULong.t

  val _CKA_WRAP_WITH_TRUSTED : Unsigned.ULong.t

  val _CKA_WRAP_TEMPLATE : Unsigned.ULong.t

  val _CKA_UNWRAP_TEMPLATE : Unsigned.ULong.t

  val _CKA_OTP_FORMAT : Unsigned.ULong.t

  val _CKA_OTP_LENGTH : Unsigned.ULong.t

  val _CKA_OTP_TIME_INTERVAL : Unsigned.ULong.t

  val _CKA_OTP_USER_FRIENDLY_MODE : Unsigned.ULong.t

  val _CKA_OTP_CHALLENGE_REQUIREMENT : Unsigned.ULong.t

  val _CKA_OTP_TIME_REQUIREMENT : Unsigned.ULong.t

  val _CKA_OTP_COUNTER_REQUIREMENT : Unsigned.ULong.t

  val _CKA_OTP_PIN_REQUIREMENT : Unsigned.ULong.t

  val _CKA_OTP_COUNTER : Unsigned.ULong.t

  val _CKA_OTP_TIME : Unsigned.ULong.t

  val _CKA_OTP_USER_IDENTIFIER : Unsigned.ULong.t

  val _CKA_OTP_SERVICE_IDENTIFIER : Unsigned.ULong.t

  val _CKA_OTP_SERVICE_LOGO : Unsigned.ULong.t

  val _CKA_OTP_SERVICE_LOGO_TYPE : Unsigned.ULong.t

  val _CKA_HW_FEATURE_TYPE : Unsigned.ULong.t

  val _CKA_RESET_ON_INIT : Unsigned.ULong.t

  val _CKA_HAS_RESET : Unsigned.ULong.t

  val _CKA_PIXEL_X : Unsigned.ULong.t

  val _CKA_PIXEL_Y : Unsigned.ULong.t

  val _CKA_RESOLUTION : Unsigned.ULong.t

  val _CKA_CHAR_ROWS : Unsigned.ULong.t

  val _CKA_CHAR_COLUMNS : Unsigned.ULong.t

  val _CKA_COLOR : Unsigned.ULong.t

  val _CKA_BITS_PER_PIXEL : Unsigned.ULong.t

  val _CKA_CHAR_SETS : Unsigned.ULong.t

  val _CKA_ENCODING_METHODS : Unsigned.ULong.t

  val _CKA_MIME_TYPES : Unsigned.ULong.t

  val _CKA_MECHANISM_TYPE : Unsigned.ULong.t

  val _CKA_REQUIRED_CMS_ATTRIBUTES : Unsigned.ULong.t

  val _CKA_DEFAULT_CMS_ATTRIBUTES : Unsigned.ULong.t

  val _CKA_SUPPORTED_CMS_ATTRIBUTES : Unsigned.ULong.t

  val _CKA_ALLOWED_MECHANISMS : Unsigned.ULong.t

  val _CKA_VENDOR_DEFINED : Unsigned.ULong.t

  val make : 'a t -> Unsigned.ULong.t
end

type pack = Pack : 'a t -> pack [@@deriving eq, ord, show, yojson]

val compare : 'a t -> 'b t -> int

type (_, _) comparison =
  | Equal : ('a, 'a) comparison
  | Not_equal : int -> ('a, 'b) comparison

val compare' : 'a t -> 'b t -> ('a, 'b) comparison

val equal : 'a t -> 'b t -> bool

val of_string : string -> pack

val to_string : 'a t -> string

val pack_to_json : pack -> Yojson.Safe.t

val elements : pack list

val known_attribute_types : string list
