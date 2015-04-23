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

def add_class(class_entry, class_list):
	# Push the old class into list
	class_list.append(dict(class_entry))
	reset_classEntry(class_entry)

def add_method_to_class(class_entry, method_entry):
	class_entry['method_list'].append(method_entry['name'] + ":"+str(method_entry['size']))
	class_entry['size'] += method_entry['size']
	reset_methodEntry(method_entry)

def analyzeDex(class_list, dex_file):
	# Data containers
	class_entry = {}
	method_entry = {}
	
	# State machine
	NOP = 0
	CLASS = 1
	METHOD = 2
	state = NOP

	reset_classEntry(class_entry)
	reset_methodEntry(method_entry)

	for l in dex_file:
		l = l.strip() 

		if state ==  NOP:
			if isClassStart(l):
				state = CLASS

		elif state ==  CLASS:
			# New class starts
			if class_entry['class_des'] != "" and class_entry['size'] > 0:
				add_class(class_entry, class_list)

			if isClassDescriptor(l): 
				class_entry['class_des']= getContent(l)

			if isMethodStart(l):
				state = METHOD

		elif state == METHOD:
			new_class =  isClassStart(l)

			if isMethodStart(l) or new_class:
				#new method, push the last method entry into class:
				if method_entry['size'] > 0:
					add_method_to_class(class_entry, method_entry)
			elif isMethodName(l):
				method_entry['name'] = getContent(l)
			elif isMethodSize(l):
				c, bit = l.split(":")[1].strip().split("-bit")[0].split()
				foot_print = int(c) * int(bit) / 8
				method_entry['size'] = foot_print

			if new_class:
				state = CLASS
		else:
			print "can't happen"

	# Push the last item into list 
	if method_entry['size'] > 0:
		add_method_to_class(class_entry, method_entry)

	if class_entry['class_des'] != "" and class_entry['size'] > 0:
		add_class(class_entry, class_list)
	
def _main():
	# Parsing the dex dump file
	dex_file = open(sys.argv[1]).readlines()

	class_list = []
	analyzeDex(class_list, dex_file)
	class_list = sorted(class_list, key = lambda i:i['size'])

	sum_size = 0
	for i in class_list:
		sum_size += i['size'] + 4
		print i['class_des'][2:-2].replace('/', '.')+","+str(i['size'])
#		for c in i['method_list']:
#			print c

	print "Summary number of class {0}, size {1}".format(len(class_list), sum_size)


_main()
