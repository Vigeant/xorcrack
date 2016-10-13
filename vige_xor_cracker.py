#!/usr/bin/env python
"""
Author: GuilT

Description: This is a tool to crack xor encoded files.
1. It finds the probable key length by splitting the cyphertext into a number of chunks and calculating the average entropy for the chunks.
When the right key length is found the average entropy drops noticeably.
2. It then performs a frequency analysis using a clear txt file provided by the user as the reference. This allows using the tool
for cracking different types of content. You can use it to crack source code, text and more.
3. It will then present the user with several samples decoded using the most probable keys. At this point, the user is likely to recognize
the text. If so, enter the sample number to decode the entire cypher text. If no correct answer is found in the samples, the user can
provide its best guess of the content (at least keylen characters) to decode the rest of the file.
"""

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
		print "keylen: %02d, average entropy: %f" % (keylen , averageent)
	
	keys = sorted(table, key=table.__getitem__)
	probablekeys = {}
	a = 1000
	for kl in keys:
		if table[kl] < a:
			a = table[kl]
		if table[kl] - a < 0.1:
			probablekeys[kl] = table[kl]
	return sorted(probablekeys)[0]

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
	
def xor(key, cyphertext):
	cleartext = ''
	for i in xrange(len(cyphertext)):
		cleartext += chr(ord(cyphertext[i]) ^ ord(key[i % len(key)]))
	return cleartext
	
def generateKeys(xorkeysvals, candidates):
	keys = {}
	keylen = len(xorkeysvals)
	for a in xrange(candidates ** keylen):
		key = ''
		aa = a
		for z in range(keylen):
			key += xorkeysvals[z][aa % candidates]
			aa = aa/candidates
		keys[a] = key
	return keys
	


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='A tool that finds the xorkey len and the key.')
	parser.add_argument('-i', type=argparse.FileType('r'),
						default=sys.stdin, help='The cypher text file to crack (default=stdin)')
	parser.add_argument('clear_infile', type=argparse.FileType('r'),
						help='The clear infile to use to compile frequencies')
	parser.add_argument('-o', type=argparse.FileType('w'),
						default=sys.stdout, help='The output file decoded (default=stdout)')
	parser.add_argument('-m',  type=int, default=10, help='The maximum xor key lenght the tool will look for')
	parser.add_argument('-l',  type=int, default=None, help='Force key len (avoid figuring it out)')
	parser.add_argument('-n',  type=int, default=2, help='Number of candidate bytes to use when generating keys for display (default n=2) (number of keys = keylen ** n')

	args = parser.parse_args()

	idata = args.i.read()#.decode('hex')
	cdata = args.clear_infile.read()
		
	if args.l:
		keylen = args.l
		print "[+] Set Key len: %d" % keylen
	else:
		keylen = findKeyLen(idata, args.m)
		print "[+] Probable Key len: %d" % keylen
		

	#clearout = ''
	xorkeysvals = []
	for i in range(keylen):
		val = computeFrequencies(cdata[i::keylen])
		key = computeFrequencies(idata[i::keylen])
		minlen = min(len(val),len(key))
		val = ''.join(val[:minlen])
		key = ''.join(key[:minlen])
		xorkeysvals += [findXorChar(val, key)[:args.n]]	
		


	print "Displaying key : sample with most probable first"
	keys = generateKeys(xorkeysvals,args.n)
	for i in xrange(len(keys)):
		print "%5d\tkey: %s sample: %r" % (i, keys[i].encode('hex'),xor(keys[i],idata[:70]))

	print "\n"

	choice = raw_input("Enter the number of the best sample above OR type your best guess for the first %d letters of the message: \n" % keylen)
	print

	try:
		choice = int(choice)
		cleartext = xor(keys[choice],idata)
		print 'key: %s' % keys[choice].encode('hex')
	except:
		if keylen <= len(choice.strip()):
			key = ''
			for i in xrange(keylen):
				key += chr(ord(choice[i]) ^ ord(idata[i]))
			print 'key: %s' % key.encode('hex')
			cleartxt = ''
			for i in xrange(len(idata)):
				cleartxt += chr(ord(idata[i]) ^ ord(key[i%keylen]))
		else:
			print 'you need to provide at least %d chars' % keylen
			quit()

		args.o.write(cleartxt)
	print "\n"
