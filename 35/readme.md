1. case of g=1, then:
public keys will be equal to 1^x==1, so that Bob will generate B=1 and
A will generate s=B^a=1^a=1

2. case of g=p-1, then
B=1|B=p-1
s=B^a=(1|p-1)^a=1|p-1

3. case of g=p, then B=0
s=0

In each case we send to B spoofed g, so that B sends back value we expect,
then we relay that value to A and we can predict s very easily after that.
