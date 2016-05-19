# xorcrack
This python script cracks xor encoded strings using frequency analysis.

It was written in a rush 2 days before nsec so it needs a good cleanup but it does the job for the competition.

The script uses argparse so use the help to see how to use it.

If not provided a keylen, it will try and figure the lenght of the key using entropy. One the keylen is found, it will generate keys using the 2 most probable characters at each position of the key figured out using a frequency analysis.

To use example provided do this:

./vige_xor_cracker.py -i cypher.txt clear_in.txt
