type t = Pkcs11.CK_INFO.u =
  {
    cryptokiVersion : P11_version.t;
    manufacturerID : string;
    flags : P11_flags.t;
    libraryDescription : string;
    libraryVersion : P11_version.t;
  }
  [@@deriving eq,show,yojson]

val to_string : ?newlines: bool -> ?indent: string -> t -> string
val to_strings:  t -> string list
val flags_to_string : P11_flags.t -> string
