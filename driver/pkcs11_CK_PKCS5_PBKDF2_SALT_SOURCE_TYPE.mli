(** Salt used in [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE]) *)
type t = P11_ulong.t [@@deriving eq, ord]

val _CKZ_SALT_SPECIFIED : t

val make : P11_pkcs5_pbkdf2_salt_source_type.t -> t

val view : t -> P11_pkcs5_pbkdf2_salt_source_type.t

val typ : t Ctypes.typ
