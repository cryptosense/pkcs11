(**
   Parameters for [CKM_AES_KEY_WRAP].
   Note that the name of this module is not in PKCS11,
   where it is just described as a nullable pointer.
*)
type t [@@deriving eq, ord, show, yojson]

val default : t
(** Use the default IV as specified in the AES-KEYWRAP specification. *)

val explicit : string -> t
(** Use this IV. It should be exactly 8 bytes long for PKCS11 compliant DLLs. *)

val explicit_iv : t -> string option
(** Return the explicit IV, or None if the default value was used. *)
