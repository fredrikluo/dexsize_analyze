#!/usr/bin/python
# -*- coding: utf-8 -*-
import os

from subprocess import Popen, PIPE
from subprocess import call

check_list = ['dex.py', 'lib/proguard_demngl.py', 'lib/printer.py']

def run_cmd(pl):
    p = Popen(pl, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    (output, err) = p.communicate()
    return (output, err, p.returncode)


# Check the pep8 style.
for i in check_list:
    (output, err, rc) = run_cmd(['pep8', i])
    if len(output.strip()) > 0:
        print i, ' Failed on pep8.'
        print output

# Run the script against testcases, should have no crashes..
testfiles = [['testcases/classes-1.dex'],
             ['testcases/classes-3.dex']]

for f in testfiles:
    plist = ['./dex.py', '-s', '-st', '-d']
    plist.extend(f)
    print 'checking:', f[0]
    (output, err, rc) = run_cmd(plist)

    # check crash.
    if rc != 0:
        print 'Cashes in:', f[0]
        print output, err
