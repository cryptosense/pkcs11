(** Object handles ([CK_OBJECT_HANDLE]) *)
type t = Pkcs11_CK_ULONG.t
[@@deriving eq,ord,show,yojson]
val typ : t Ctypes.typ
