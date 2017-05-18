type t =
  { major : int
  ; minor : int
  }
[@@deriving eq,show,yojson]

let to_string version =
  Printf.sprintf "%i.%i" version.major version.minor
