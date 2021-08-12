type t =
  | Index of int
  | Id of int
  | Description of string
  | Label of string
[@@deriving eq, ord, show]

let to_yojson = function
  | Index x -> `List [`String "index"; `Int x]
  | Id x -> `List [`String "id"; `Int x]
  | Description x -> `List [`String "description"; `String x]
  | Label x -> `List [`String "label"; `String x]

let of_yojson = function
  | `List [`String "index"; `Int x] -> Ok (Index x)
  | `List [`String "id"; `Int x] -> Ok (Id x)
  | `List [`String "description"; `String x] -> Ok (Description x)
  | `List [`String "label"; `String x] -> Ok (Label x)
  | _ -> Error "Slot.t"

let default = Index 0

let to_string = function
  | Index i -> ("slot index", string_of_int i)
  | Id i -> ("slot ID", string_of_int i)
  | Description s -> ("slot description", s)
  | Label s -> ("token label", s)
