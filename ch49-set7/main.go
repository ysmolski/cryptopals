// Challenge 49: CBC-MAC Message Forgery
//
// Suppose there's an online banking application, and it carries out user requests
// by talking to an API server over the network. Each request looks like this:
//     message || IV || MAC
//
// The message looks like this:
//     from=#{from_id}&to=#{to_id}&amount=#{amount}
//
// Solution to this problem depends on the width of IDs. Suppose that IDs are
// short: less than 3 decimals. "from" and "to" fits into the first block (16 bytes):
//
//     1st block       2               3
//     from=101&to=105&amount=10000
//
// Then attack is trivial. We can forge first block whenever we want and XOR
// forged block with original, and set new_IV=IV XOR (P1 XOR new_P1)
//
// Suppose that IDS are longer than 3 decimals. But the "from" id fits the 1st
// block still:
//
//     1st block       2               3
//     from=10000000001&to=1000000005&amount=10000
//
// In this case attacker can try to send money from one of this own accounts to
// another account of his:
//
//     1st block       2               3
//     from=10000000006&to=1000000005&amount=10000
//
// And then he can forge the first block replace the "from" id to the id of the
// victims as described before.
//
// If the "from" id does not fit the the first block then we are most likely out of luck.
// import "fmt"
//
// 2nd part:
// captured message from the target user:
//
//     1st block       2               3
//     from=10000000012&tx_list=1000006:103;1000007:213
//
// We need to forge signature for the message:
//
//     1st block       2               3               6
//     from=10000000012&tx_list=1000006:103;1000007:213;attacker:10000000
//
// This challenge says that we can produce only signed messages for the
// accounts that are owned by the attacker. We cannot make client sign just an
// appendix "attacker:100000". Using the length extension attack, we can just
// append the whole message produced by the attacker and im not sure that
// even the most stupid server api would accept such a message.
//
// The 2nd part is too vague, and I don't like this lack of restrictions.
//
package main

import "fmt"

func main() {
	fmt.Println("I am bored with frivolous wording of the challenge.")
}
