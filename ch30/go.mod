module main

go 1.18

replace tools => ../tools

require tools v1.0.0

replace md4 v1.0.0 => ./md4

require md4 v1.0.0
