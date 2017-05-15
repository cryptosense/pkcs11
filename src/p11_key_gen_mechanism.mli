type t = Pkcs11.Key_gen_mechanism.u =
  | CKM of P11_mechanism_type.t
  | CK_UNAVAILABLE_INFORMATION 
[@@deriving yojson]
