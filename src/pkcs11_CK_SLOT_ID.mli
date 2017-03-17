(** Slot identifiers ([CK_SLOT_ID]) *)
type t = Pkcs11_CK_ULONG.t
[@@deriving eq,ord,show,yojson]
val typ : t Ctypes.typ
