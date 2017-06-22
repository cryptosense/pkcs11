(** PRF used to generate the key in [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE]) *)
type t = P11_ulong.t

val _CKP_PKCS5_PBKD2_HMAC_SHA1 : t

val make : P11_pkcs5_pbkd2_pseudo_random_function_type.t -> t

val view : t -> P11_pkcs5_pbkd2_pseudo_random_function_type.t

val typ : t Ctypes.typ
