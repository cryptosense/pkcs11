(** Object handles ([CK_OBJECT_HANDLE]) *)
type t = Pkcs11_CK_ULONG.t
val typ : t Ctypes.typ
