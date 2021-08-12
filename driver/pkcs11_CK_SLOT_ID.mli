(** Slot identifiers ([CK_SLOT_ID]) *)
type t = P11_ulong.t [@@deriving eq, ord, show, yojson]

val typ : t Ctypes.typ
