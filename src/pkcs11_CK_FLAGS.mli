(** Bit flags used in several places ([CK_FLAGS]) *)
type t = Pkcs11_CK_ULONG.t

val empty : t
val compare : t -> t -> int
val equal : t -> t -> bool
val logical_or : t -> t -> t
val ( || ) : t -> t -> t
val ( && ) : t -> t -> t

(** [get flags flag] returns true if flag is set in flags. *)
val get : flags: t -> flag: t -> bool

(**
 * Domains used to distinguish flag values.
 * Any_domain is for flags that can be used across all domains.
*)
type domain =
  | Info_domain
  | Slot_info_domain
  | Token_info_domain
  | Session_info_domain
  | Mechanism_info_domain
  | Initialize_domain
  | Wait_for_slot_domain
  | OTP_signature_info_domain
  | Any_domain

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

(** Returns list of (flag, flag pretty string) for the given domain *)
val flags_of_domain : domain -> (t * string) list

(**
 * Split a combined flag value into a list of all the flags it comprises.
 * Returns tuple of list of known (flag, pretty string) for the domain and
 * unknown remaining flags.
*)
val split_with_string : domain -> t -> ((t * string) list * t)

(**
 * Split a combined flag value into a list of all the flags it comprises.
 * Returns tuple of list of known flags for the domain and unknown remaining
 * flags.
*)
val split : domain -> t -> t list * t

(** Returns pretty strings for flags separated with | for the given domain. *)
val to_pretty_string : domain -> t -> string

(** Returns list of pretty strings for flags for the given domain. *)
val to_pretty_strings : domain -> t -> string list

val t : t Ctypes.typ
