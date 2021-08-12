type t = P11_attribute_type.pack list [@@deriving eq, ord, show, yojson]

let mem template x =
  let open P11_attribute_type in
  let ok (Pack ty) = equal ty x in
  List.exists ok template

let rec remove_duplicates l acc =
  match l with
  | [] -> List.rev acc
  | (P11_attribute_type.Pack ty as p) :: q ->
    if mem acc ty then
      remove_duplicates q acc
    else
      remove_duplicates q (p :: acc)

let remove_duplicates l = remove_duplicates l []
