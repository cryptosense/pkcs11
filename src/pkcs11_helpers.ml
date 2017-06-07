(** Miscellaneous helpers *)

let string_of_record
    ?(newlines = false)
    ?(indent = "")
    (fields: (string * string) list): string =
  let first_separator = if newlines then "" else "{ " in
  let separator = if newlines then "\n" else "; " in
  let last_separator = if newlines then "" else " }" in
  let first = ref true in
  [
    List.flatten (
      List.map
        (fun (name, value) ->
           [ if !first then (first := false; first_separator) else separator;
             indent; name; ": "; value ])
        fields
    );
    [ last_separator ];
  ]
  |> List.flatten
  |> String.concat ""

let strings_of_record =
  List.map
    (fun (name, value) ->
       Printf.sprintf "%s: %s" name value
    )

let of_json_string ~typename of_string json =
  let err msg =
    Error (Printf.sprintf "(while parsing %s): %s" typename msg)
  in
  match json with
  | `String s ->
    begin
      try
        Ok (of_string s)
      with Invalid_argument _ ->
        err "of_string failed"
    end
  | _ -> err "Not a JSON string"
