(** Token information. *)
type _t

type t = _t Ctypes.structure

val make : P11_token_info.t -> t

val view : t -> P11_token_info.t

val ck_token_info : t Ctypes.typ
