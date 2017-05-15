include Pkcs11.CK_FLAGS

let to_json ?pretty (flags:t) =
  match pretty with
    | None ->
      Pkcs11_CK_ULONG.to_yojson flags
    | Some pretty ->
        `Assoc [
          "value", Pkcs11_CK_ULONG.to_yojson flags;
          "string", `String (pretty flags);
        ]

type has_value =
  { value : Yojson.Safe.json
  ; string : string
  }
[@@deriving of_yojson]

let of_yojson json =
  (* We know that [Pkcs11_CK_ULONG.to_yojson] does not produce [`Assoc]s. *)
  let actual_json = match has_value_of_yojson json with
    | Ok { value } -> value
    | Error _ -> json
  in
  Pkcs11_CK_ULONG.of_yojson actual_json

let to_yojson =
  to_json ?pretty:None
