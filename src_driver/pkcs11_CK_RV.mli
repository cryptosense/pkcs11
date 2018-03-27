(** Return values. *)
type t = P11_ulong.t
[@@deriving eq,ord]

val _CKR_OK : t
val _CKR_CANCEL : t
val _CKR_HOST_MEMORY : t
val _CKR_SLOT_ID_INVALID : t
val _CKR_GENERAL_ERROR : t
val _CKR_FUNCTION_FAILED : t
val _CKR_ARGUMENTS_BAD : t
val _CKR_NO_EVENT : t
val _CKR_NEED_TO_CREATE_THREADS : t
val _CKR_CANT_LOCK : t
val _CKR_ATTRIBUTE_READ_ONLY : t
val _CKR_ATTRIBUTE_SENSITIVE : t
val _CKR_ATTRIBUTE_TYPE_INVALID : t
val _CKR_ATTRIBUTE_VALUE_INVALID : t
val _CKR_ACTION_PROHIBITED : t
val _CKR_DATA_INVALID : t
val _CKR_DATA_LEN_RANGE : t
val _CKR_DEVICE_ERROR : t
val _CKR_DEVICE_MEMORY : t
val _CKR_DEVICE_REMOVED : t
val _CKR_ENCRYPTED_DATA_INVALID : t
val _CKR_ENCRYPTED_DATA_LEN_RANGE : t
val _CKR_FUNCTION_CANCELED : t
val _CKR_FUNCTION_NOT_PARALLEL : t
val _CKR_FUNCTION_NOT_SUPPORTED : t
val _CKR_KEY_HANDLE_INVALID : t
val _CKR_KEY_SIZE_RANGE : t
val _CKR_KEY_TYPE_INCONSISTENT : t
val _CKR_KEY_NOT_NEEDED : t
val _CKR_KEY_CHANGED : t
val _CKR_KEY_NEEDED : t
val _CKR_KEY_INDIGESTIBLE : t
val _CKR_KEY_FUNCTION_NOT_PERMITTED : t
val _CKR_KEY_NOT_WRAPPABLE : t
val _CKR_KEY_UNEXTRACTABLE : t
val _CKR_MECHANISM_INVALID : t
val _CKR_MECHANISM_PARAM_INVALID : t
val _CKR_OBJECT_HANDLE_INVALID : t
val _CKR_OPERATION_ACTIVE : t
val _CKR_OPERATION_NOT_INITIALIZED : t
val _CKR_PIN_INCORRECT : t
val _CKR_PIN_INVALID : t
val _CKR_PIN_LEN_RANGE : t
val _CKR_PIN_EXPIRED : t
val _CKR_PIN_LOCKED : t
val _CKR_SESSION_CLOSED : t
val _CKR_SESSION_COUNT : t
val _CKR_SESSION_HANDLE_INVALID : t
val _CKR_SESSION_PARALLEL_NOT_SUPPORTED : t
val _CKR_SESSION_READ_ONLY : t
val _CKR_SESSION_EXISTS : t
val _CKR_SESSION_READ_ONLY_EXISTS : t
val _CKR_SESSION_READ_WRITE_SO_EXISTS : t
val _CKR_SIGNATURE_INVALID : t
val _CKR_SIGNATURE_LEN_RANGE : t
val _CKR_TEMPLATE_INCOMPLETE : t
val _CKR_TEMPLATE_INCONSISTENT : t
val _CKR_TOKEN_NOT_PRESENT : t
val _CKR_TOKEN_NOT_RECOGNIZED : t
val _CKR_TOKEN_WRITE_PROTECTED : t
val _CKR_UNWRAPPING_KEY_HANDLE_INVALID : t
val _CKR_UNWRAPPING_KEY_SIZE_RANGE : t
val _CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT : t
val _CKR_USER_ALREADY_LOGGED_IN : t
val _CKR_USER_NOT_LOGGED_IN : t
val _CKR_USER_PIN_NOT_INITIALIZED : t
val _CKR_USER_TYPE_INVALID : t
val _CKR_USER_ANOTHER_ALREADY_LOGGED_IN : t
val _CKR_USER_TOO_MANY_TYPES : t
val _CKR_WRAPPED_KEY_INVALID : t
val _CKR_WRAPPED_KEY_LEN_RANGE : t
val _CKR_WRAPPING_KEY_HANDLE_INVALID : t
val _CKR_WRAPPING_KEY_SIZE_RANGE : t
val _CKR_WRAPPING_KEY_TYPE_INCONSISTENT : t
val _CKR_RANDOM_SEED_NOT_SUPPORTED : t
val _CKR_RANDOM_NO_RNG : t
val _CKR_DOMAIN_PARAMS_INVALID : t
val _CKR_CURVE_NOT_SUPPORTED : t
val _CKR_BUFFER_TOO_SMALL : t
val _CKR_SAVED_STATE_INVALID : t
val _CKR_INFORMATION_SENSITIVE : t
val _CKR_STATE_UNSAVEABLE : t
val _CKR_CRYPTOKI_NOT_INITIALIZED : t
val _CKR_CRYPTOKI_ALREADY_INITIALIZED : t
val _CKR_MUTEX_BAD : t
val _CKR_MUTEX_NOT_LOCKED : t
val _CKR_NEW_PIN_MODE : t
val _CKR_NEXT_OTP : t
val _CKR_EXCEEDED_MAX_ITERATIONS : t
val _CKR_FIPS_SELF_TEST_FAILED : t
val _CKR_LIBRARY_LOAD_FAILED : t
val _CKR_PIN_TOO_WEAK : t
val _CKR_PUBLIC_KEY_INVALID : t
val _CKR_FUNCTION_REJECTED : t
val _CKR_VENDOR_DEFINED : t

val typ : t Ctypes.typ

val view : t -> P11_rv.t

val make : P11_rv.t -> t