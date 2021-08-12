(**
   Big integers used in PKCS#11.

   PKCS#11 expects them to be encoded in big-endian,
   so manipulating the underlying representation is error-prone.
*)

type t [@@deriving eq, ord, show, yojson]

val encode : t -> string
(** Convert to/from a big-endian byte array. *)

val decode : string -> t

val to_int : t -> int

val of_int : int -> t

val to_string : t -> string

val zero : t

val of_z : Z.t -> t

val to_z : t -> Z.t
