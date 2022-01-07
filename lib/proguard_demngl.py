#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys


class ProgardDemangle(object):

    def __init__(self, mapfile):
        self.symbol_list = {}
        self.type_rlist = {}

        if mapfile:
            fl = open(mapfile).readlines()
            self._loadData(fl)

    def _loadData(self, fl):

        # build type list
        type_list = {}

        for l in fl:
            if l and not l.startswith(' ') and not l.startswith('#'):
                (org_name, mangled_name) = self._getMapping(l)
                type_list[mangled_name] = org_name
                self.type_rlist[org_name] = mangled_name

        # build signature map

        class_name = None
        for l in fl:
            if not l or l.strip().startswith('#'):
                continue

            (org_name, mangled_name) = self._getMapping(l)
            if not l.startswith(' '):
                class_name = mangled_name
            elif class_name and org_name.find('(') != -1:
                sig = self._get_sig(l)
                self.symbol_list[class_name + '_' + sig] = org_name

        for k in type_list.keys():
            self.symbol_list[k] = type_list[k]

    def _get_sig(self, l):
        (org_name, mangled_name) = self._getMapping(l)
        (n, p) = org_name.strip().split('(')

        # parameter_list

        if p != ')':
            pl = p[:-1].split(',')
            pl_m = []
            for i in pl:
                if i in self.type_rlist:
                    pl_m.append(self.type_rlist[i])
                else:
                    pl_m.append(i)

            return (mangled_name + '_' + '_'.join(pl_m) if pl_m else '')
        else:
            return mangled_name

    def _getMapping(self, l):
        try:
            (org_name, mangled_name) = l.strip().split('->')
        except:
            print(l)
            print("testing")
            sys.stdout.flush()
            raise
        o_l = org_name.split(':')

        if len(o_l) == 3:
            _org_name = o_l[2]
        else:
            _org_name = org_name

        if not l.startswith(' ') and l.strip().endswith(':'):
            mangled_name = mangled_name.strip()[:-1]

        return (_org_name.strip(), mangled_name.strip())

    def getSymbol(self, sig):
        sym = None
        if sig.find('<') != -1:

            # special function

            s_list = sig.split('_')
            rs_list = []
            for i in s_list:
                if i.startswith('<'):
                    rs_list.append(i)
                else:
                    rs_list.append(self.getSymbol(i))

            return '_'.join(rs_list)

        try:

            sym = self.symbol_list[sig]
        except KeyError:
            sym = sig

        return sym

    def test(self):

        def test_verify(a, b):
            if a != b:
                print 'Verify failed: ', a, b
            else:
                print 'Verify succeed: ', a, b

        fl = [
            'android.support.v4.app.ActivityCompatHoneycomb -> a:\n',
            '   android.support.v4.app.ActivityCompatHoneycomb'
            ' next$fe619d5 -> a\n',
            '   36:39:android.os.Parcelable$Creator newCreator'
            '(android.support.v4.os.ParcelableCompatCreatorCallbacks) -> a\n',
            '   106:120:java.util.Map loadSearchHotWordItems() -> b\n',
            '   254:255:java.lang.Object getField(java.lang.Object,'
            'java.lang.String,java.lang.Object) -> a\n',
            'com.opera.android.statistic.EventLogger$Name -> ckm:\n',
            'android.support.v4.os.ParcelableCompatCreatorCallbacks -> c\n',
            ]

        self._loadData(fl)
        test_verify(self.getSymbol('a'),
                    'android.support.v4.app.ActivityCompatHoneycomb')
        test_verify(self.getSymbol('a_a_c'),
                    'android.os.Parcelable$Creator newCreator'
                    '(android.support.v4.os.ParcelableCompatCreatorCallbacks)')
        test_verify(self.getSymbol('a_b'),
                    'java.util.Map loadSearchHotWordItems()')
        test_verify(self.getSymbol('a_a_java.lang.Object_java.'
                                   'lang.String_java.lang.Object'),
                    'java.lang.Object getField'
                    '(java.lang.Object,java.lang.String,java.lang.Object)')
        print '# Dump the symbol list:'
        print self.symbol_list


if __name__ == '__main__':
    d = ProgardDemangle(None)
    d.test()
