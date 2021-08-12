(** Attribute types ([CK_ATTRIBUTE_TYPE]) *)

type t = P11_ulong.t [@@deriving eq, ord]

val _CKA_CLASS : t

val _CKA_TOKEN : t

val _CKA_PRIVATE : t

val _CKA_LABEL : t

val _CKA_APPLICATION : t

val _CKA_VALUE : t

val _CKA_OBJECT_ID : t

val _CKA_CERTIFICATE_TYPE : t

val _CKA_ISSUER : t

val _CKA_SERIAL_NUMBER : t

val _CKA_AC_ISSUER : t

val _CKA_OWNER : t

val _CKA_ATTR_TYPES : t

val _CKA_TRUSTED : t

val _CKA_CERTIFICATE_CATEGORY : t

val _CKA_JAVA_MIDP_SECURITY_DOMAIN : t

val _CKA_URL : t

val _CKA_HASH_OF_SUBJECT_PUBLIC_KEY : t

val _CKA_HASH_OF_ISSUER_PUBLIC_KEY : t

val _CKA_CHECK_VALUE : t

val _CKA_KEY_TYPE : t

val _CKA_SUBJECT : t

val _CKA_ID : t

val _CKA_SENSITIVE : t

val _CKA_ENCRYPT : t

val _CKA_DECRYPT : t

val _CKA_WRAP : t

val _CKA_UNWRAP : t

val _CKA_SIGN : t

val _CKA_SIGN_RECOVER : t

val _CKA_VERIFY : t

val _CKA_VERIFY_RECOVER : t

val _CKA_DERIVE : t

val _CKA_START_DATE : t

val _CKA_END_DATE : t

val _CKA_MODULUS : t

val _CKA_MODULUS_BITS : t

val _CKA_PUBLIC_EXPONENT : t

val _CKA_PRIVATE_EXPONENT : t

val _CKA_PRIME_1 : t

val _CKA_PRIME_2 : t

val _CKA_EXPONENT_1 : t

val _CKA_EXPONENT_2 : t

val _CKA_COEFFICIENT : t

val _CKA_PRIME : t

val _CKA_SUBPRIME : t

val _CKA_BASE : t

val _CKA_PRIME_BITS : t

val _CKA_SUBPRIME_BITS : t

(* val _CKA_SUB_PRIME_BITS : t *)
val _CKA_VALUE_BITS : t

val _CKA_VALUE_LEN : t

val _CKA_EXTRACTABLE : t

val _CKA_LOCAL : t

val _CKA_NEVER_EXTRACTABLE : t

val _CKA_ALWAYS_SENSITIVE : t

val _CKA_KEY_GEN_MECHANISM : t

val _CKA_MODIFIABLE : t

(* val _CKA_ECDSA_PARAMS : t deprecated, and equal to EC_PARAMS *)
val _CKA_EC_PARAMS : t

val _CKA_EC_POINT : t

val _CKA_SECONDARY_AUTH : t

val _CKA_AUTH_PIN_FLAGS : t

val _CKA_ALWAYS_AUTHENTICATE : t

val _CKA_WRAP_WITH_TRUSTED : t

val _CKA_WRAP_TEMPLATE : t

val _CKA_UNWRAP_TEMPLATE : t

val _CKA_OTP_FORMAT : t

val _CKA_OTP_LENGTH : t

val _CKA_OTP_TIME_INTERVAL : t

val _CKA_OTP_USER_FRIENDLY_MODE : t

val _CKA_OTP_CHALLENGE_REQUIREMENT : t

val _CKA_OTP_TIME_REQUIREMENT : t

val _CKA_OTP_COUNTER_REQUIREMENT : t

val _CKA_OTP_PIN_REQUIREMENT : t

val _CKA_OTP_COUNTER : t

val _CKA_OTP_TIME : t

val _CKA_OTP_USER_IDENTIFIER : t

val _CKA_OTP_SERVICE_IDENTIFIER : t

val _CKA_OTP_SERVICE_LOGO : t

val _CKA_OTP_SERVICE_LOGO_TYPE : t

val _CKA_HW_FEATURE_TYPE : t

val _CKA_RESET_ON_INIT : t

val _CKA_HAS_RESET : t

val _CKA_PIXEL_X : t

val _CKA_PIXEL_Y : t

val _CKA_RESOLUTION : t

val _CKA_CHAR_ROWS : t

val _CKA_CHAR_COLUMNS : t

val _CKA_COLOR : t

val _CKA_BITS_PER_PIXEL : t

val _CKA_CHAR_SETS : t

val _CKA_ENCODING_METHODS : t

val _CKA_MIME_TYPES : t

val _CKA_MECHANISM_TYPE : t

val _CKA_REQUIRED_CMS_ATTRIBUTES : t

val _CKA_DEFAULT_CMS_ATTRIBUTES : t

val _CKA_SUPPORTED_CMS_ATTRIBUTES : t

val _CKA_ALLOWED_MECHANISMS : t

val _CKA_VENDOR_DEFINED : t

val make : 'a P11_attribute_type.t -> t

val view : t -> P11_attribute_type.pack

val typ : t Ctypes.typ
