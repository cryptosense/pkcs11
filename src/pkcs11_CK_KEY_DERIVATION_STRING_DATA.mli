type _t
type t = _t Ctypes.structure

type u = string

val make: u -> t
val view: t -> u

val t : t Ctypes.typ
