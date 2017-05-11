type t =
  { iv: string
  ; data: string
  }
[@@deriving yojson]

let compare a b =
  let c = String.compare a.iv b.iv in
  if c <> 0 then
    c
  else
    String.compare a.data b.data
