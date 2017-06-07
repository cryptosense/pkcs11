type t = P11_ulong.t
[@@deriving eq,ord]

let view_error n =
  Pkcs11_log.log @@ Printf.sprintf
    "Unknown CKR code: 0x%Lx" n

external identity : 'a -> 'a = "%identity"

let typ =
  let open Ctypes in
  view ~read:identity ~write:identity ulong

let with_value x = Unsigned.ULong.of_string @@ Int64.to_string x

let _CKR_OK                               = with_value 0x00000000L
let _CKR_CANCEL                           = with_value 0x00000001L
let _CKR_HOST_MEMORY                      = with_value 0x00000002L
let _CKR_SLOT_ID_INVALID                  = with_value 0x00000003L
let _CKR_GENERAL_ERROR                    = with_value 0x00000005L
let _CKR_FUNCTION_FAILED                  = with_value 0x00000006L
let _CKR_ARGUMENTS_BAD                    = with_value 0x00000007L
let _CKR_NO_EVENT                         = with_value 0x00000008L
let _CKR_NEED_TO_CREATE_THREADS           = with_value 0x00000009L
let _CKR_CANT_LOCK                        = with_value 0x0000000AL
let _CKR_ATTRIBUTE_READ_ONLY              = with_value 0x00000010L
let _CKR_ATTRIBUTE_SENSITIVE              = with_value 0x00000011L
let _CKR_ATTRIBUTE_TYPE_INVALID           = with_value 0x00000012L
let _CKR_ATTRIBUTE_VALUE_INVALID          = with_value 0x00000013L
let _CKR_DATA_INVALID                     = with_value 0x00000020L
let _CKR_DATA_LEN_RANGE                   = with_value 0x00000021L
let _CKR_DEVICE_ERROR                     = with_value 0x00000030L
let _CKR_DEVICE_MEMORY                    = with_value 0x00000031L
let _CKR_DEVICE_REMOVED                   = with_value 0x00000032L
let _CKR_ENCRYPTED_DATA_INVALID           = with_value 0x00000040L
let _CKR_ENCRYPTED_DATA_LEN_RANGE         = with_value 0x00000041L
let _CKR_FUNCTION_CANCELED                = with_value 0x00000050L
let _CKR_FUNCTION_NOT_PARALLEL            = with_value 0x00000051L
let _CKR_FUNCTION_NOT_SUPPORTED           = with_value 0x00000054L
let _CKR_KEY_HANDLE_INVALID               = with_value 0x00000060L
let _CKR_KEY_SIZE_RANGE                   = with_value 0x00000062L
let _CKR_KEY_TYPE_INCONSISTENT            = with_value 0x00000063L
let _CKR_KEY_NOT_NEEDED                   = with_value 0x00000064L
let _CKR_KEY_CHANGED                      = with_value 0x00000065L
let _CKR_KEY_NEEDED                       = with_value 0x00000066L
let _CKR_KEY_INDIGESTIBLE                 = with_value 0x00000067L
let _CKR_KEY_FUNCTION_NOT_PERMITTED       = with_value 0x00000068L
let _CKR_KEY_NOT_WRAPPABLE                = with_value 0x00000069L
let _CKR_KEY_UNEXTRACTABLE                = with_value 0x0000006AL
let _CKR_MECHANISM_INVALID                = with_value 0x00000070L
let _CKR_MECHANISM_PARAM_INVALID          = with_value 0x00000071L
let _CKR_OBJECT_HANDLE_INVALID            = with_value 0x00000082L
let _CKR_OPERATION_ACTIVE                 = with_value 0x00000090L
let _CKR_OPERATION_NOT_INITIALIZED        = with_value 0x00000091L
let _CKR_PIN_INCORRECT                    = with_value 0x000000A0L
let _CKR_PIN_INVALID                      = with_value 0x000000A1L
let _CKR_PIN_LEN_RANGE                    = with_value 0x000000A2L
let _CKR_PIN_EXPIRED                      = with_value 0x000000A3L
let _CKR_PIN_LOCKED                       = with_value 0x000000A4L
let _CKR_SESSION_CLOSED                   = with_value 0x000000B0L
let _CKR_SESSION_COUNT                    = with_value 0x000000B1L
let _CKR_SESSION_HANDLE_INVALID           = with_value 0x000000B3L
let _CKR_SESSION_PARALLEL_NOT_SUPPORTED   = with_value 0x000000B4L
let _CKR_SESSION_READ_ONLY                = with_value 0x000000B5L
let _CKR_SESSION_EXISTS                   = with_value 0x000000B6L
let _CKR_SESSION_READ_ONLY_EXISTS         = with_value 0x000000B7L
let _CKR_SESSION_READ_WRITE_SO_EXISTS     = with_value 0x000000B8L
let _CKR_SIGNATURE_INVALID                = with_value 0x000000C0L
let _CKR_SIGNATURE_LEN_RANGE              = with_value 0x000000C1L
let _CKR_TEMPLATE_INCOMPLETE              = with_value 0x000000D0L
let _CKR_TEMPLATE_INCONSISTENT            = with_value 0x000000D1L
let _CKR_TOKEN_NOT_PRESENT                = with_value 0x000000E0L
let _CKR_TOKEN_NOT_RECOGNIZED             = with_value 0x000000E1L
let _CKR_TOKEN_WRITE_PROTECTED            = with_value 0x000000E2L
let _CKR_UNWRAPPING_KEY_HANDLE_INVALID    = with_value 0x000000F0L
let _CKR_UNWRAPPING_KEY_SIZE_RANGE        = with_value 0x000000F1L
let _CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = with_value 0x000000F2L
let _CKR_USER_ALREADY_LOGGED_IN           = with_value 0x00000100L
let _CKR_USER_NOT_LOGGED_IN               = with_value 0x00000101L
let _CKR_USER_PIN_NOT_INITIALIZED         = with_value 0x00000102L
let _CKR_USER_TYPE_INVALID                = with_value 0x00000103L
let _CKR_USER_ANOTHER_ALREADY_LOGGED_IN   = with_value 0x00000104L
let _CKR_USER_TOO_MANY_TYPES              = with_value 0x00000105L
let _CKR_WRAPPED_KEY_INVALID              = with_value 0x00000110L
let _CKR_WRAPPED_KEY_LEN_RANGE            = with_value 0x00000112L
let _CKR_WRAPPING_KEY_HANDLE_INVALID      = with_value 0x00000113L
let _CKR_WRAPPING_KEY_SIZE_RANGE          = with_value 0x00000114L
let _CKR_WRAPPING_KEY_TYPE_INCONSISTENT   = with_value 0x00000115L
let _CKR_RANDOM_SEED_NOT_SUPPORTED        = with_value 0x00000120L
let _CKR_RANDOM_NO_RNG                    = with_value 0x00000121L
let _CKR_DOMAIN_PARAMS_INVALID            = with_value 0x00000130L
let _CKR_BUFFER_TOO_SMALL                 = with_value 0x00000150L
let _CKR_SAVED_STATE_INVALID              = with_value 0x00000160L
let _CKR_INFORMATION_SENSITIVE            = with_value 0x00000170L
let _CKR_STATE_UNSAVEABLE                 = with_value 0x00000180L
let _CKR_CRYPTOKI_NOT_INITIALIZED         = with_value 0x00000190L
let _CKR_CRYPTOKI_ALREADY_INITIALIZED     = with_value 0x00000191L
let _CKR_MUTEX_BAD                        = with_value 0x000001A0L
let _CKR_MUTEX_NOT_LOCKED                 = with_value 0x000001A1L
let _CKR_NEW_PIN_MODE                     = with_value 0x000001B0L
let _CKR_NEXT_OTP                         = with_value 0x000001B1L
let _CKR_FUNCTION_REJECTED                = with_value 0x00000200L
let _CKR_VENDOR_DEFINED                   = with_value 0x80000000L

let make u =
  let open P11_rv in
  match u with
    | CKR_OK  -> _CKR_OK
    | CKR_CANCEL  -> _CKR_CANCEL
    | CKR_HOST_MEMORY  -> _CKR_HOST_MEMORY
    | CKR_SLOT_ID_INVALID  -> _CKR_SLOT_ID_INVALID
    | CKR_GENERAL_ERROR  -> _CKR_GENERAL_ERROR
    | CKR_FUNCTION_FAILED  -> _CKR_FUNCTION_FAILED
    | CKR_ARGUMENTS_BAD  -> _CKR_ARGUMENTS_BAD
    | CKR_NO_EVENT  -> _CKR_NO_EVENT
    | CKR_NEED_TO_CREATE_THREADS  -> _CKR_NEED_TO_CREATE_THREADS
    | CKR_CANT_LOCK  -> _CKR_CANT_LOCK
    | CKR_ATTRIBUTE_READ_ONLY  -> _CKR_ATTRIBUTE_READ_ONLY
    | CKR_ATTRIBUTE_SENSITIVE  -> _CKR_ATTRIBUTE_SENSITIVE
    | CKR_ATTRIBUTE_TYPE_INVALID  -> _CKR_ATTRIBUTE_TYPE_INVALID
    | CKR_ATTRIBUTE_VALUE_INVALID  -> _CKR_ATTRIBUTE_VALUE_INVALID
    | CKR_DATA_INVALID  -> _CKR_DATA_INVALID
    | CKR_DATA_LEN_RANGE  -> _CKR_DATA_LEN_RANGE
    | CKR_DEVICE_ERROR  -> _CKR_DEVICE_ERROR
    | CKR_DEVICE_MEMORY  -> _CKR_DEVICE_MEMORY
    | CKR_DEVICE_REMOVED  -> _CKR_DEVICE_REMOVED
    | CKR_ENCRYPTED_DATA_INVALID  -> _CKR_ENCRYPTED_DATA_INVALID
    | CKR_ENCRYPTED_DATA_LEN_RANGE  -> _CKR_ENCRYPTED_DATA_LEN_RANGE
    | CKR_FUNCTION_CANCELED  -> _CKR_FUNCTION_CANCELED
    | CKR_FUNCTION_NOT_PARALLEL  -> _CKR_FUNCTION_NOT_PARALLEL
    | CKR_FUNCTION_NOT_SUPPORTED  -> _CKR_FUNCTION_NOT_SUPPORTED
    | CKR_KEY_HANDLE_INVALID  -> _CKR_KEY_HANDLE_INVALID
    | CKR_KEY_SIZE_RANGE  -> _CKR_KEY_SIZE_RANGE
    | CKR_KEY_TYPE_INCONSISTENT  -> _CKR_KEY_TYPE_INCONSISTENT
    | CKR_KEY_NOT_NEEDED  -> _CKR_KEY_NOT_NEEDED
    | CKR_KEY_CHANGED  -> _CKR_KEY_CHANGED
    | CKR_KEY_NEEDED  -> _CKR_KEY_NEEDED
    | CKR_KEY_INDIGESTIBLE  -> _CKR_KEY_INDIGESTIBLE
    | CKR_KEY_FUNCTION_NOT_PERMITTED  -> _CKR_KEY_FUNCTION_NOT_PERMITTED
    | CKR_KEY_NOT_WRAPPABLE  -> _CKR_KEY_NOT_WRAPPABLE
    | CKR_KEY_UNEXTRACTABLE  -> _CKR_KEY_UNEXTRACTABLE
    | CKR_MECHANISM_INVALID  -> _CKR_MECHANISM_INVALID
    | CKR_MECHANISM_PARAM_INVALID  -> _CKR_MECHANISM_PARAM_INVALID
    | CKR_OBJECT_HANDLE_INVALID  -> _CKR_OBJECT_HANDLE_INVALID
    | CKR_OPERATION_ACTIVE  -> _CKR_OPERATION_ACTIVE
    | CKR_OPERATION_NOT_INITIALIZED  -> _CKR_OPERATION_NOT_INITIALIZED
    | CKR_PIN_INCORRECT  -> _CKR_PIN_INCORRECT
    | CKR_PIN_INVALID  -> _CKR_PIN_INVALID
    | CKR_PIN_LEN_RANGE  -> _CKR_PIN_LEN_RANGE
    | CKR_PIN_EXPIRED  -> _CKR_PIN_EXPIRED
    | CKR_PIN_LOCKED  -> _CKR_PIN_LOCKED
    | CKR_SESSION_CLOSED  -> _CKR_SESSION_CLOSED
    | CKR_SESSION_COUNT  -> _CKR_SESSION_COUNT
    | CKR_SESSION_HANDLE_INVALID  -> _CKR_SESSION_HANDLE_INVALID
    | CKR_SESSION_PARALLEL_NOT_SUPPORTED  -> _CKR_SESSION_PARALLEL_NOT_SUPPORTED
    | CKR_SESSION_READ_ONLY  -> _CKR_SESSION_READ_ONLY
    | CKR_SESSION_EXISTS  -> _CKR_SESSION_EXISTS
    | CKR_SESSION_READ_ONLY_EXISTS  -> _CKR_SESSION_READ_ONLY_EXISTS
    | CKR_SESSION_READ_WRITE_SO_EXISTS  -> _CKR_SESSION_READ_WRITE_SO_EXISTS
    | CKR_SIGNATURE_INVALID  -> _CKR_SIGNATURE_INVALID
    | CKR_SIGNATURE_LEN_RANGE  -> _CKR_SIGNATURE_LEN_RANGE
    | CKR_TEMPLATE_INCOMPLETE  -> _CKR_TEMPLATE_INCOMPLETE
    | CKR_TEMPLATE_INCONSISTENT  -> _CKR_TEMPLATE_INCONSISTENT
    | CKR_TOKEN_NOT_PRESENT  -> _CKR_TOKEN_NOT_PRESENT
    | CKR_TOKEN_NOT_RECOGNIZED  -> _CKR_TOKEN_NOT_RECOGNIZED
    | CKR_TOKEN_WRITE_PROTECTED  -> _CKR_TOKEN_WRITE_PROTECTED
    | CKR_UNWRAPPING_KEY_HANDLE_INVALID  -> _CKR_UNWRAPPING_KEY_HANDLE_INVALID
    | CKR_UNWRAPPING_KEY_SIZE_RANGE  -> _CKR_UNWRAPPING_KEY_SIZE_RANGE
    | CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  -> _CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
    | CKR_USER_ALREADY_LOGGED_IN  -> _CKR_USER_ALREADY_LOGGED_IN
    | CKR_USER_NOT_LOGGED_IN  -> _CKR_USER_NOT_LOGGED_IN
    | CKR_USER_PIN_NOT_INITIALIZED  -> _CKR_USER_PIN_NOT_INITIALIZED
    | CKR_USER_TYPE_INVALID  -> _CKR_USER_TYPE_INVALID
    | CKR_USER_ANOTHER_ALREADY_LOGGED_IN  -> _CKR_USER_ANOTHER_ALREADY_LOGGED_IN
    | CKR_USER_TOO_MANY_TYPES  -> _CKR_USER_TOO_MANY_TYPES
    | CKR_WRAPPED_KEY_INVALID  -> _CKR_WRAPPED_KEY_INVALID
    | CKR_WRAPPED_KEY_LEN_RANGE  -> _CKR_WRAPPED_KEY_LEN_RANGE
    | CKR_WRAPPING_KEY_HANDLE_INVALID  -> _CKR_WRAPPING_KEY_HANDLE_INVALID
    | CKR_WRAPPING_KEY_SIZE_RANGE  -> _CKR_WRAPPING_KEY_SIZE_RANGE
    | CKR_WRAPPING_KEY_TYPE_INCONSISTENT  -> _CKR_WRAPPING_KEY_TYPE_INCONSISTENT
    | CKR_RANDOM_SEED_NOT_SUPPORTED  -> _CKR_RANDOM_SEED_NOT_SUPPORTED
    | CKR_RANDOM_NO_RNG  -> _CKR_RANDOM_NO_RNG
    | CKR_DOMAIN_PARAMS_INVALID  -> _CKR_DOMAIN_PARAMS_INVALID
    | CKR_BUFFER_TOO_SMALL  -> _CKR_BUFFER_TOO_SMALL
    | CKR_SAVED_STATE_INVALID  -> _CKR_SAVED_STATE_INVALID
    | CKR_INFORMATION_SENSITIVE  -> _CKR_INFORMATION_SENSITIVE
    | CKR_STATE_UNSAVEABLE  -> _CKR_STATE_UNSAVEABLE
    | CKR_CRYPTOKI_NOT_INITIALIZED  -> _CKR_CRYPTOKI_NOT_INITIALIZED
    | CKR_CRYPTOKI_ALREADY_INITIALIZED  -> _CKR_CRYPTOKI_ALREADY_INITIALIZED
    | CKR_MUTEX_BAD  -> _CKR_MUTEX_BAD
    | CKR_MUTEX_NOT_LOCKED  -> _CKR_MUTEX_NOT_LOCKED
    | CKR_NEW_PIN_MODE  -> _CKR_NEW_PIN_MODE
    | CKR_NEXT_OTP  -> _CKR_NEXT_OTP
    | CKR_FUNCTION_REJECTED  -> _CKR_FUNCTION_REJECTED
    | CKR_VENDOR_DEFINED  -> _CKR_VENDOR_DEFINED
    | CKR_CS_UNKNOWN x -> x

let view t =
  let open P11_rv in
  let is value = Unsigned.ULong.compare t value = 0 in
  match () with
    | _ when is _CKR_OK -> CKR_OK
    | _ when is _CKR_CANCEL -> CKR_CANCEL
    | _ when is _CKR_HOST_MEMORY -> CKR_HOST_MEMORY
    | _ when is _CKR_SLOT_ID_INVALID -> CKR_SLOT_ID_INVALID
    | _ when is _CKR_GENERAL_ERROR -> CKR_GENERAL_ERROR
    | _ when is _CKR_FUNCTION_FAILED -> CKR_FUNCTION_FAILED
    | _ when is _CKR_ARGUMENTS_BAD -> CKR_ARGUMENTS_BAD
    | _ when is _CKR_NO_EVENT -> CKR_NO_EVENT
    | _ when is _CKR_NEED_TO_CREATE_THREADS -> CKR_NEED_TO_CREATE_THREADS
    | _ when is _CKR_CANT_LOCK -> CKR_CANT_LOCK
    | _ when is _CKR_ATTRIBUTE_READ_ONLY -> CKR_ATTRIBUTE_READ_ONLY
    | _ when is _CKR_ATTRIBUTE_SENSITIVE -> CKR_ATTRIBUTE_SENSITIVE
    | _ when is _CKR_ATTRIBUTE_TYPE_INVALID -> CKR_ATTRIBUTE_TYPE_INVALID
    | _ when is _CKR_ATTRIBUTE_VALUE_INVALID -> CKR_ATTRIBUTE_VALUE_INVALID
    | _ when is _CKR_DATA_INVALID -> CKR_DATA_INVALID
    | _ when is _CKR_DATA_LEN_RANGE -> CKR_DATA_LEN_RANGE
    | _ when is _CKR_DEVICE_ERROR -> CKR_DEVICE_ERROR
    | _ when is _CKR_DEVICE_MEMORY -> CKR_DEVICE_MEMORY
    | _ when is _CKR_DEVICE_REMOVED -> CKR_DEVICE_REMOVED
    | _ when is _CKR_ENCRYPTED_DATA_INVALID -> CKR_ENCRYPTED_DATA_INVALID
    | _ when is _CKR_ENCRYPTED_DATA_LEN_RANGE -> CKR_ENCRYPTED_DATA_LEN_RANGE
    | _ when is _CKR_FUNCTION_CANCELED -> CKR_FUNCTION_CANCELED
    | _ when is _CKR_FUNCTION_NOT_PARALLEL -> CKR_FUNCTION_NOT_PARALLEL
    | _ when is _CKR_FUNCTION_NOT_SUPPORTED -> CKR_FUNCTION_NOT_SUPPORTED
    | _ when is _CKR_KEY_HANDLE_INVALID -> CKR_KEY_HANDLE_INVALID
    | _ when is _CKR_KEY_SIZE_RANGE -> CKR_KEY_SIZE_RANGE
    | _ when is _CKR_KEY_TYPE_INCONSISTENT -> CKR_KEY_TYPE_INCONSISTENT
    | _ when is _CKR_KEY_NOT_NEEDED -> CKR_KEY_NOT_NEEDED
    | _ when is _CKR_KEY_CHANGED -> CKR_KEY_CHANGED
    | _ when is _CKR_KEY_NEEDED -> CKR_KEY_NEEDED
    | _ when is _CKR_KEY_INDIGESTIBLE -> CKR_KEY_INDIGESTIBLE
    | _ when is _CKR_KEY_FUNCTION_NOT_PERMITTED -> CKR_KEY_FUNCTION_NOT_PERMITTED
    | _ when is _CKR_KEY_NOT_WRAPPABLE -> CKR_KEY_NOT_WRAPPABLE
    | _ when is _CKR_KEY_UNEXTRACTABLE -> CKR_KEY_UNEXTRACTABLE
    | _ when is _CKR_MECHANISM_INVALID -> CKR_MECHANISM_INVALID
    | _ when is _CKR_MECHANISM_PARAM_INVALID -> CKR_MECHANISM_PARAM_INVALID
    | _ when is _CKR_OBJECT_HANDLE_INVALID -> CKR_OBJECT_HANDLE_INVALID
    | _ when is _CKR_OPERATION_ACTIVE -> CKR_OPERATION_ACTIVE
    | _ when is _CKR_OPERATION_NOT_INITIALIZED -> CKR_OPERATION_NOT_INITIALIZED
    | _ when is _CKR_PIN_INCORRECT -> CKR_PIN_INCORRECT
    | _ when is _CKR_PIN_INVALID -> CKR_PIN_INVALID
    | _ when is _CKR_PIN_LEN_RANGE -> CKR_PIN_LEN_RANGE
    | _ when is _CKR_PIN_EXPIRED -> CKR_PIN_EXPIRED
    | _ when is _CKR_PIN_LOCKED -> CKR_PIN_LOCKED
    | _ when is _CKR_SESSION_CLOSED -> CKR_SESSION_CLOSED
    | _ when is _CKR_SESSION_COUNT -> CKR_SESSION_COUNT
    | _ when is _CKR_SESSION_HANDLE_INVALID -> CKR_SESSION_HANDLE_INVALID
    | _ when is _CKR_SESSION_PARALLEL_NOT_SUPPORTED -> CKR_SESSION_PARALLEL_NOT_SUPPORTED
    | _ when is _CKR_SESSION_READ_ONLY -> CKR_SESSION_READ_ONLY
    | _ when is _CKR_SESSION_EXISTS -> CKR_SESSION_EXISTS
    | _ when is _CKR_SESSION_READ_ONLY_EXISTS -> CKR_SESSION_READ_ONLY_EXISTS
    | _ when is _CKR_SESSION_READ_WRITE_SO_EXISTS -> CKR_SESSION_READ_WRITE_SO_EXISTS
    | _ when is _CKR_SIGNATURE_INVALID -> CKR_SIGNATURE_INVALID
    | _ when is _CKR_SIGNATURE_LEN_RANGE -> CKR_SIGNATURE_LEN_RANGE
    | _ when is _CKR_TEMPLATE_INCOMPLETE -> CKR_TEMPLATE_INCOMPLETE
    | _ when is _CKR_TEMPLATE_INCONSISTENT -> CKR_TEMPLATE_INCONSISTENT
    | _ when is _CKR_TOKEN_NOT_PRESENT -> CKR_TOKEN_NOT_PRESENT
    | _ when is _CKR_TOKEN_NOT_RECOGNIZED -> CKR_TOKEN_NOT_RECOGNIZED
    | _ when is _CKR_TOKEN_WRITE_PROTECTED -> CKR_TOKEN_WRITE_PROTECTED
    | _ when is _CKR_UNWRAPPING_KEY_HANDLE_INVALID -> CKR_UNWRAPPING_KEY_HANDLE_INVALID
    | _ when is _CKR_UNWRAPPING_KEY_SIZE_RANGE -> CKR_UNWRAPPING_KEY_SIZE_RANGE
    | _ when is _CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT -> CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
    | _ when is _CKR_USER_ALREADY_LOGGED_IN -> CKR_USER_ALREADY_LOGGED_IN
    | _ when is _CKR_USER_NOT_LOGGED_IN -> CKR_USER_NOT_LOGGED_IN
    | _ when is _CKR_USER_PIN_NOT_INITIALIZED -> CKR_USER_PIN_NOT_INITIALIZED
    | _ when is _CKR_USER_TYPE_INVALID -> CKR_USER_TYPE_INVALID
    | _ when is _CKR_USER_ANOTHER_ALREADY_LOGGED_IN -> CKR_USER_ANOTHER_ALREADY_LOGGED_IN
    | _ when is _CKR_USER_TOO_MANY_TYPES -> CKR_USER_TOO_MANY_TYPES
    | _ when is _CKR_WRAPPED_KEY_INVALID -> CKR_WRAPPED_KEY_INVALID
    | _ when is _CKR_WRAPPED_KEY_LEN_RANGE -> CKR_WRAPPED_KEY_LEN_RANGE
    | _ when is _CKR_WRAPPING_KEY_HANDLE_INVALID -> CKR_WRAPPING_KEY_HANDLE_INVALID
    | _ when is _CKR_WRAPPING_KEY_SIZE_RANGE -> CKR_WRAPPING_KEY_SIZE_RANGE
    | _ when is _CKR_WRAPPING_KEY_TYPE_INCONSISTENT -> CKR_WRAPPING_KEY_TYPE_INCONSISTENT
    | _ when is _CKR_RANDOM_SEED_NOT_SUPPORTED -> CKR_RANDOM_SEED_NOT_SUPPORTED
    | _ when is _CKR_RANDOM_NO_RNG -> CKR_RANDOM_NO_RNG
    | _ when is _CKR_DOMAIN_PARAMS_INVALID -> CKR_DOMAIN_PARAMS_INVALID
    | _ when is _CKR_BUFFER_TOO_SMALL -> CKR_BUFFER_TOO_SMALL
    | _ when is _CKR_SAVED_STATE_INVALID -> CKR_SAVED_STATE_INVALID
    | _ when is _CKR_INFORMATION_SENSITIVE -> CKR_INFORMATION_SENSITIVE
    | _ when is _CKR_STATE_UNSAVEABLE -> CKR_STATE_UNSAVEABLE
    | _ when is _CKR_CRYPTOKI_NOT_INITIALIZED -> CKR_CRYPTOKI_NOT_INITIALIZED
    | _ when is _CKR_CRYPTOKI_ALREADY_INITIALIZED -> CKR_CRYPTOKI_ALREADY_INITIALIZED
    | _ when is _CKR_MUTEX_BAD -> CKR_MUTEX_BAD
    | _ when is _CKR_MUTEX_NOT_LOCKED -> CKR_MUTEX_NOT_LOCKED
    | _ when is _CKR_NEW_PIN_MODE -> CKR_NEW_PIN_MODE
    | _ when is _CKR_NEXT_OTP -> CKR_NEXT_OTP
    | _ when is _CKR_FUNCTION_REJECTED -> CKR_FUNCTION_REJECTED
    | _ when is _CKR_VENDOR_DEFINED -> CKR_VENDOR_DEFINED
    | _ -> (view_error (Int64.of_string (Unsigned.ULong.to_string t)); CKR_CS_UNKNOWN t)
