#!/usr/bin/python

import dvm
import sys

class Dex_printer(object):
      def Print(self, i, idx = 0):
         self.idx = idx
         _str = ""

         if isinstance(i,  dvm.StringIdItem):
            _str = self._printStrId(i)
         elif isinstance(i, dvm.HeaderItem):
            _str = self._printHeader(i)
         elif isinstance(i, dvm.AnnotationItem):
            _str = self._printAnn(i)
         elif isinstance(i, dvm.AnnotationSetItem):
            _str = self._printAnnSet(i)
         elif isinstance(i, dvm.AnnotationsDirectoryItem):
            _str = self._printAnnDic(i)
         elif isinstance(i, dvm.AnnotationSetRefItem):
            _str = self._printAnnSetRef(i)
         #elif isinstance(i, dvm.MapItem):
         #   _str = self._printMapItem(i)
         elif isinstance(i, dvm.StringDataItem):
            _str = self._printStrData(i)
         elif isinstance(i, dvm.DebugInfoItem):
            _str = self._printDbgInfo(i)
         elif isinstance(i, dvm.EncodedArrayItem):
            _str = self._printEncodedAry(i)
         elif isinstance(i, dvm.ClassDataItem):
            _str = self._printClassData(i)
         elif isinstance(i, dvm.TypeIdItem):
            _str = self._printTypeId(i)
         elif isinstance(i, dvm.TypeItem):
            _str = self._printTypeItem(i)
         elif isinstance(i, dvm.ProtoIdItem):
            _str = self._printProtoId(i)
         elif isinstance(i, dvm.FieldIdItem):
            _str = self._printFieldId(i)
         elif isinstance(i, dvm.MethodIdItem):
            _str = self._printMethId(i)
         elif isinstance(i, dvm.ClassDefItem):
            _str = self._printClassDef(i)
         elif isinstance(i, dvm.DalvikCode):
            _str = self._printDalvikCode(i)
         elif isinstance(i, dvm.TypeList):
            _str = self._printTypeList(i)
         elif isinstance(i, dvm.MapList):
            _str = self._printMapList(i)
         elif isinstance(i, dvm.AnnotationSetRefList):
            _str = self._printAnnotationSetRefList(i)
         else:
            assert(not "bug bug")

         return _str
       
      def _printStrId(self, i):
          return "String Id", str(self.idx)

      def _printStrData(self, i):
          return "String:"+str(self.idx), i.get_data()[:50]

      def _printHeader(self, i):
          return "Header",""

      def _printAnn(self, i):
          return "Annotation",""

      def _printAnnSet(self, i):
          return "AnnotationSet",""

      def _printAnnSetRef(self, i):
          return "AnnotationSet ref",""

      def _printAnnDic(self, i):
          return "Annotation dir",""

      def _printAnnotationSetRefList(self, i):
          return "AnnotationSet reflist",""

      def _printMapList(self, i):
          return "Map list",""

      def _printDbgInfo(self, i):
          return "Debug info",""

      def _printEncodedAry(self, i):
          return "Encoded array",""

      #def _printClassData(self, i):
      #    return "Class data",""

      def _printTypeId(self, i):
          return "Type id:"+ str(self.idx), i.get_descriptor_idx_value()

      def _printTypeItem(self, i):
          return "Type item", i.get_string()

      def _printTypeList(self, i):
          return "Type list",""

      def _printProtoId(self, i):
          return "Proto id:" + str(self.idx), "des:{0}{1}".format(i.shorty_idx_value, i.parameters_off_value)

      def _printFieldId(self, i):
          return "Field id:" + str(self.idx), i.get_class_name()+":"+i.get_name()

      def _printMethId(self, i):
          return "Method id", str(self.idx)

      def _printClassDef(self, i):
          return "Class", i.get_name()[1:-1].replace("/", ".")

#      def _printDalvikCode(self, i):
 #         return "Method",""

