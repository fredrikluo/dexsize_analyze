import sys

def getContent(c):
	return c.split(':')[1].strip()

def isClassStart(l):
	return l.startswith("Class #")

def isMethodStart(l):
	return l.startswith("#")

def isClassDescriptor(l): 
	return l.startswith("Class descriptor")

def isMethodName(l):
	return l.startswith("name")

def isMethodSize(l):
	return l.startswith("insns")

def reset_classEntry(c):
	c['class_des'] = ""
	c['method_list'] = []
	c['size'] = 0

def reset_methodEntry(m):
	m['name'] = ""
	m['size'] = 0

# Data containers
class_list = []
class_entry = {}
method_entry = {}

# State machine
NOP = 0
CLASS = 1
METHOD = 2
state = NOP

# Parsing the dex dump file
dex_file = open(sys.argv[1]).readlines()

reset_classEntry(class_entry)
reset_methodEntry(method_entry)

for l in dex_file:
	l = l.strip() 

	if state ==  NOP:
		if isClassStart(l):
			state = CLASS

	elif state ==  CLASS:
		# New class starts
		# Push the old class into list
		if class_entry['class_des'] != "":
			class_list.append(dict(class_entry))
			reset_classEntry(class_entry)

		if isClassDescriptor(l): 
			class_entry['class_des']= getContent(l)

		if isMethodStart("#"):
			state = METHOD

	elif state == METHOD:
		if isClassStart(l):
			state = CLASS

		if isMethodStart(l):
			#new method, push the last method entry into class:
			if method_entry['size'] > 0:
				class_entry['method_list'].append(method_entry['name'] + ":"+str(method_entry['size']))
				class_entry['size'] += method_entry['size']

			reset_methodEntry(method_entry)

		if isMethodName(l):
			method_entry['name'] = getContent(l)

		if isMethodSize(l):
			c, bit = l.split(":")[1].strip().split("-bit")[0].split()
			foot_print = int(c)*int(bit)/8
			method_entry['size'] = foot_print
	else:
		print "can't happen"


class_list = sorted(class_list, key = lambda i:i['size'])

for i in class_list:
	print "Class descriptor:"+i['class_des']+" size:"+str(i['size'])
	for c in i['method_list']:
		print "   "+ c
