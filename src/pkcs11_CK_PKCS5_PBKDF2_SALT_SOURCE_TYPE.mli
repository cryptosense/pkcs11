(** Salt used in [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE]) *)
type t = Pkcs11_CK_ULONG.t

type u =
  | CKZ_SALT_SPECIFIED

val _CKZ_SALT_SPECIFIED : t
val to_string : u -> string
val of_string : string -> u

val make : u -> t
val view : t -> u

val typ : t Ctypes.typ
