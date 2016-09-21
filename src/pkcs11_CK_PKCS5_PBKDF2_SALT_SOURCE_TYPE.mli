type t = Pkcs11_CK_ULONG.t

type u =
  | CKZ_SALT_SPECIFIED

val _CKZ_SALT_SPECIFIED : t
val to_string : u -> string
val of_string : string -> u

val make : u -> t
val view : t -> u

val typ : t Ctypes.typ
