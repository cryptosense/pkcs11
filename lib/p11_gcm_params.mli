(**
   Parameter for AES GCM.
   In PKCS11 applications:
   - the length of [iv] can be any number between 1 and 256.
   - [tag_bits] can be any value between 0 and 128.

   These invariants are not checked, in order to represent invalid states that
   DLLs may return.
*)

type t [@@deriving eq, ord, show, yojson]

val make : iv:string -> aad:string -> tag_bits:P11_ulong.t -> t

val iv : t -> string

val aad : t -> string

val tag_bits : t -> P11_ulong.t
