(** How the interaction is done with the DLL. *)
type t = private
  | Auto
  | FFI
[@@deriving eq, ord, show, yojson]

val ffi : t
(** Call directly each symbol using libffi. *)

val auto : t
(**
   Call C_GetFunctionList using libffi.
   For each symbol, try to access it through the returned function list.
   Otherwise, call the symbol directly.
*)
