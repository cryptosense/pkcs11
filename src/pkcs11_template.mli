(** Low-level interface to templates (arrays of attributes) *)
type t = Pkcs11_CK_ATTRIBUTE.t Ctypes.carray
val of_list : Pkcs11_CK_ATTRIBUTE.t list -> t
val allocate : t -> unit
val to_list : t -> Pkcs11_CK_ATTRIBUTE.t list

type u = Pkcs11_CK_ATTRIBUTE.pack list
val make : u -> t
val view : t -> u
