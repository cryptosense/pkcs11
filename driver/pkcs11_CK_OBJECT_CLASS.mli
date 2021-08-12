(** Object types ([CK_OBJECT_CLASS]) *)

type t = P11_ulong.t

val _CKO_DATA : t

val _CKO_CERTIFICATE : t

val _CKO_PUBLIC_KEY : t

val _CKO_PRIVATE_KEY : t

val _CKO_SECRET_KEY : t

val _CKO_HW_FEATURE : t

val _CKO_DOMAIN_PARAMETERS : t

val _CKO_MECHANISM : t

val _CKO_OTP_KEY : t

val _CKO_VENDOR_DEFINED : t

val typ : t Ctypes.typ

val view : t -> P11_object_class.t

val make : P11_object_class.t -> t
