(** PRF used to generate the key in [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE]) *)
type t = Pkcs11_CK_ULONG.t

type u =
  | CKP_PKCS5_PBKD2_HMAC_SHA1

val _CKP_PKCS5_PBKD2_HMAC_SHA1 : t
val to_string : u -> string
val of_string : string -> u

val make : u -> t
val view : t -> u

val typ : t Ctypes.typ
