type t =
  { major : int
  ; minor : int }
[@@deriving eq, ord, show, yojson]

let to_string version = Printf.sprintf "%i.%i" version.major version.minor
