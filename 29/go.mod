module main

go 1.18

replace tools => ../tools

require tools v1.0.0

replace sha1go v1.0.0 => ./sha1go

require sha1go v1.0.0
