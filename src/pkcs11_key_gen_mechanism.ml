type t = Pkcs11_CK_ULONG.t

type u =
  | CKM of Pkcs11_CK_MECHANISM_TYPE.u
  | CK_UNAVAILABLE_INFORMATION

let compare a b = match a,b with
  | CK_UNAVAILABLE_INFORMATION, CK_UNAVAILABLE_INFORMATION -> 0
  | CKM x , CKM y -> Pkcs11_CK_MECHANISM_TYPE.compare x y
  | CKM _, CK_UNAVAILABLE_INFORMATION -> 1
  | CK_UNAVAILABLE_INFORMATION, CKM _ -> -1

let view x =
  if Pkcs11_CK_ULONG.is_unavailable_information x
  then CK_UNAVAILABLE_INFORMATION
  else CKM (Pkcs11_CK_MECHANISM_TYPE.view x)

let make = function
  | CKM x -> Pkcs11_CK_MECHANISM_TYPE.make x
  | CK_UNAVAILABLE_INFORMATION -> Pkcs11_CK_ULONG._CK_UNAVAILABLE_INFORMATION

let to_string = function
  | CKM x -> Pkcs11_CK_MECHANISM_TYPE.to_string x
  | CK_UNAVAILABLE_INFORMATION -> "CK_UNAVAILABLE_INFORMATION"

let of_string = function
  | "CK_UNAVAILABLE_INFORMATION" -> CK_UNAVAILABLE_INFORMATION
  | s -> CKM (Pkcs11_CK_MECHANISM_TYPE.of_string s)
