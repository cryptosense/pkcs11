(** Low-level interface to templates (arrays of attributes) *)
type t = Pkcs11_CK_ATTRIBUTE.t Ctypes.carray

val of_list : Pkcs11_CK_ATTRIBUTE.t list -> t

val allocate : t -> unit

val to_list : t -> Pkcs11_CK_ATTRIBUTE.t list

val make : P11_template.t -> t

val view : t -> P11_template.t
