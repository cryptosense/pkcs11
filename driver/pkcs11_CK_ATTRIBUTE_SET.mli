val set_access_error : Pkcs11_CK_ATTRIBUTE.t -> unit
(** Functions to populate a CK_ATTRIBUTE.t in the way of getAttributeValue.
    Populate the given t with the given value.
      - if value is none, then ulValueLen will be -1.
      - if value exist but buffer is too small, ulValueLen will be value size
      and result will be Buffer_too_small.
      - if value exist but pValue is null_ptr, ulValueLen will be value size.
      - if value exist and the buffer can be used, value will be set in pValue
      and ulValueLen will be value size.
*)

val update : P11_attribute.pack -> Pkcs11_CK_ATTRIBUTE.t -> P11_rv.t
