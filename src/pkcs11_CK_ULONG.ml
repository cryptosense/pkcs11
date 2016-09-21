type t = Unsigned.ulong
let compare = Unsigned.ULong.compare

let (!) x  = Unsigned.ULong.of_string (Int64.to_string x)
let _CK_UNAVAILABLE_INFORMATION = ! (Int64.lognot 0x0L)
let _CK_EFFECTIVELY_INFINITE = Unsigned.ULong.zero

let is_unavailable_information t = (compare t _CK_UNAVAILABLE_INFORMATION) = 0
let is_effectively_infinite t = (compare t _CK_EFFECTIVELY_INFINITE) = 0
