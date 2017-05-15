type t = Pkcs11.CK_DES_CBC_ENCRYPT_DATA_PARAMS.u =
  {
    iv: string;
    data: string;
  }
[@@deriving yojson]
