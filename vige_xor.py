#!/usr/bin/env python

import argparse
import sys

parser = argparse.ArgumentParser(description='A tool that encodes a file using a xor key')
parser.add_argument('key',  help='The xor key to encode the file with')
parser.add_argument('clear_infile', type=argparse.FileType('r'),
					help='The clear infile to encode')
parser.add_argument('-o', type=argparse.FileType('w'),
					default=sys.stdout, help='The output file (default=stdout)')

args = parser.parse_args()

keylen = len(args.key)
while True:
	chunk = args.clear_infile.read(keylen)
	if not chunk:
		break
	cipher = ''
	for i in range(len(chunk)):
		cipher += chr(ord(args.key[i]) ^ ord(chunk[i]))
	args.o.write(cipher)
