#!/usr/bin/env python

import argparse
import sys
import entropy
from string import maketrans

def findKeyLen(data, maxKeyLen):
	table = {}
	for keylen in range(1,maxKeyLen):
		entsum = 0
		for i in range(keylen):
			subtable = data[i::keylen]
			entsum += entropy.shannon_entropy(subtable)
		averageent = entsum / keylen
		table[keylen] = averageent
		print "keylen: %d, averageent: %f" % (keylen , averageent)
	return sorted(table, key=table.__getitem__)[0]
	

def computeFrequencies(data):
	freqs = {}
	for c in data:
		try:
			freqs[c] += 1
		except:
			freqs[c] = 1
	return sorted(freqs, key=freqs.__getitem__)[::-1]
	
def findXorChar(str1, str2):
	xork = {}
	for i in xrange(256):
		xork[chr(i)] = 0
		
		for j in xrange(len(str1)):
			if ord(str1[j]) ^ i == ord(str2[j]):
				xork[chr(i)] += 1
	return sorted(xork, key=xork.__getitem__)[::-1]
	
parser = argparse.ArgumentParser(description='A tool that finds the xorkey len and the key.')
parser.add_argument('-i', type=argparse.FileType('r'),
					default=sys.stdin, help='The cypher text file to crack (default=stdin)')
parser.add_argument('clear_infile', type=argparse.FileType('r'),
					help='The clear infile to use to compile frequencies')
parser.add_argument('-o', type=argparse.FileType('w'),
					default=sys.stdout, help='The output file decoded (default=stdout)')
parser.add_argument('-m',  type=int, default=10, help='The maximum xor key lenght the tool will look for')
parser.add_argument('-l',  type=int, default=None, help='Force key len (avoid figuring it out)')

args = parser.parse_args()

idata = args.i.read()
cdata = args.clear_infile.read()
	
if args.l:
	keylen = args.l
	print "[+] Set Key len: %d" % keylen
else:
	keylen = findKeyLen(idata, args.m)
	print "[+] Probable Key len: %d" % keylen
	

#print args
keycandidates = 2
clearout = ''
xorkeysvals = []
for i in range(keylen):
	val = computeFrequencies(cdata[i::keylen])
	key = computeFrequencies(idata[i::keylen])
	minlen = min(len(val),len(key))
	val = ''.join(val[:minlen])
	key = ''.join(key[:minlen])
	#print val
	#print key
	xorkeysvals += [findXorChar(val, key)[:keycandidates]]
	

def decrypt(a, samplesize, final):
	temp = a
	buf = ''
	if samplesize < 0:
		samplesize = len(idata)
	for z in range(keylen):
		buf += xorkeysvals[z][temp % 2]
		temp = temp/2
		
	sample = ''
	
	for i in xrange(samplesize):
		sample += chr(ord(idata[i]) ^ ord(buf[i%keylen]))
	
	if final:
		args.o.write("%5d\tkey: %r sample: \n\n%s" %(a, buf, sample))
	else:
		print "%5d\tkey: %r sample: %r" %(a, buf, sample)	

print "Displaying key : sample with most probable first"
for a in xrange(keycandidates ** keylen):
	decrypt(a,70, False)
print "\n\n"
choice = int(raw_input("Enter the number of the best sample above: "))
print "\n\n"
decrypt(choice,-1, True)




