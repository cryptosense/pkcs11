type t = Pkcs11_CK_ULONG.t

type u =
  | CKM of Pkcs11_CK_MECHANISM_TYPE.u
  | CK_UNAVAILABLE_INFORMATION
val to_string : u -> string
val of_string : string -> u
val make : u -> t
val view : t -> u
val compare : u -> u -> int
