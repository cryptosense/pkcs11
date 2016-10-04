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

