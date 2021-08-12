(** Parameters for [CKM_PKCS5_PBKD2] ([CK_PKCS5_PBKD2_PARAMS]) *)
type _t

type t = _t Ctypes.structure

val make : P11_pkcs5_pbkd2_data_params.t -> t

val view : t -> P11_pkcs5_pbkd2_data_params.t

val t : t Ctypes.typ
