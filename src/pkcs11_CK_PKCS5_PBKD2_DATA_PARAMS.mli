(** Parameters for [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKD2_PARAMS]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    saltSource: Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.u;
    saltSourceData: string option;
    iterations: int;
    prf: Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.u;
    prfData: string option;
    password: string;
  }

val make: u -> t
val view: t -> u

val compare : u -> u -> int

val t : t Ctypes.typ
