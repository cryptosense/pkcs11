(** Parameters for [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKD2_PARAMS]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    saltSource: P11_pkcs5_pbkdf2_salt_source_type.t;
    saltSourceData: string option;
    iterations: int;
    prf: P11_pkcs5_pbkd2_pseudo_random_function_type.t;
    prfData: string option;
    password: string;
  }

val make: u -> t
val view: t -> u

val compare : u -> u -> int

val t : t Ctypes.typ
