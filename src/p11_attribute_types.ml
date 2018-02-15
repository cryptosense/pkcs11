type t = P11_attribute_type.pack list
[@@deriving eq,ord,yojson]

let rec mem: type a . t -> a P11_attribute_type.t -> bool = fun template x ->
  match template with
    | [] -> false
    | head :: tail ->
        match head with
          | P11_attribute_type.Pack ty ->
              match P11_attribute_type.compare' ty x with
                | P11_attribute_type.Equal -> true
                | P11_attribute_type.Not_equal _ -> mem tail x

let rec remove_duplicates l acc =
  match l with
    | [] -> List.rev acc
    | (P11_attribute_type.Pack ty as p)::q ->
        if mem acc ty
        then remove_duplicates q acc
        else remove_duplicates q (p::acc)

let remove_duplicates l = remove_duplicates l []
