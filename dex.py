#!/usr/bin/python

import dvm
import sys
import printer 

class DexTreeItem(object):
      def __init__(self, obj, size, parent = None, idx = 0):
          self.obj = obj
          self.size = size
          self.child = []
          self.ref_count = 0
          self.parent = parent
          self.cum = 0
          self.idx = idx
          self.class_node = None

class MapListItemAccessor(object):
      def __init__(self, obj):
          self.obj = obj

      def get_obj(self):
          if type(self.obj) is list:
             return self.obj

          if (type(self.obj) is dvm.HeaderItem or 
              type(self.obj) is dvm.MapList):
             return [self.obj]

          if hasattr(self.obj, "get_obj"):
             return self.obj.get_obj()

          return []

class Dex(object):
    def __init__(self,filename, progon = True):
        if filename == None: 
            raise(Exception("Null File Name."))        

        self.filename = filename
        self.progon = progon

    def _proginfo(self, str):
        print str 

    def analyze(self):
        self._proginfo("Loading the dex file...")
        self._dex = dvm.DalvikVMFormat(open(self.filename).read(), 'rb')

        # All the items in the Dex file
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            setattr(self, name, {} if k >= 0x1000 else [])

        # Build the map items
        self._proginfo("Building map from dexfile...")
        self._build_map()

        # Build the reference tree 
        self._proginfo("Solving all the references...")
        self._build_reference_tree()

        # Build the reference count
        self._proginfo("Calculating reference counters...")
        self._build_refcount()

        # Output statistics
        self._proginfo("Generating statistics...")
        self._output_statistics()

        # Sanity test
        # self._unreferenced_check()
 
        # Inspect map
        # self._inspect_map()

    def _build_map(self):
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            obj_ls = MapListItemAccessor(self._dex.map_list.get_item_type( name )).get_obj()

            for idx, obj in enumerate(obj_ls):
                item = DexTreeItem(obj, obj.meta_size, None, idx)
                if k >= 0x1000:
                   getattr(self, name)[obj.get_off()] = item
                else:
                   getattr(self, name).append(item)

    def _connect_ref(self, ls, target, target_idx):
        ls.child.append(target[target_idx])
        target[target_idx].parent = ls

    def _connect_encoded_value(self, i, x, stringids, typeids, fieldids, methodids):
        vt = x.get_value_type()
        if vt == dvm.VALUE_STRING:
           self._connect_ref(i, stringids, x.mapped_id)
        elif vt == dvm.VALUE_TYPE:
            self._connect_ref(i, typeids,  x.mapped_id)
        elif vt == dvm.VALUE_FIELD:
            self._connect_ref(i, fieldids, x.mapped_id)
        elif vt == dvm.VALUE_METHOD:
            self._connect_ref(i, methodids, x.mapped_id)
        elif vt == dvm.VALUE_ANNOTATION:
            self._connect_encoded_annotation(i, x.value, stringids, typeids, fieldids, methodids)
        elif vt == dvm.VALUE_ARRAY:
            self._connect_encoded_array_item(i, x.value, stringids, typeids, fieldids, methodids)
        elif vt == dvm.VALUE_ENUM:
            self._connect_ref(i, fieldids, x.mapped_id)
        else:
            pass

    def _connect_encoded_annotation(self, i, obj, stringids, typeids, fieldids, methodids):
        self._connect_ref(i, typeids,   int(obj.type_idx))
        for idx in range (0, int(obj.size)):
            self._connect_ref(i, stringids,  int(obj.elements[idx].name_idx))
            self._connect_encoded_value(i, obj.elements[idx].value, stringids, typeids, fieldids, methodids)

    def _connect_encoded_array_item(self, i, obj, stringids, typeids, fieldids, methodids):
        for x in obj.get_values():
            self._connect_encoded_value(i, x, stringids, typeids, fieldids, methodids)

    def _build_reference_tree(self):
        # header has no reference items
        # maplists = dvm.TYPE_MAP_ITEM[0x1000]
        # ingore the map list for now
        maplists = getattr(self, dvm.TYPE_MAP_ITEM[0x1000])

        # Node with no reference to others
        stringdatas = getattr(self, dvm.TYPE_MAP_ITEM[0x2002])

        # string_id
        stringids = getattr(self, dvm.TYPE_MAP_ITEM[0x0001])
        for i in stringids:
            self._connect_ref(i, stringdatas, i.obj.string_data_off)

        # type_id
        typeids = getattr(self, dvm.TYPE_MAP_ITEM[0x0002])
        for i in typeids:
            self._connect_ref(i, stringids, i.obj.descriptor_idx)

        # debuginfos
        debuginfos = getattr(self, dvm.TYPE_MAP_ITEM[0x2003])
        for k in debuginfos.keys():
            i  = debuginfos[k]
            # parameter_names
            for pi in i.obj.get_parameter_names():
                self._connect_ref(i, stringids, pi)

            # dissemble the debug code to find the string reference. 
            for d in i.obj.get_bytecodes():
                # find the string reference.
                bcode_value = d.get_op_value()
                if bcode_value == dvm.DBG_START_LOCAL:
                   name_idx = d.format[1][0]
                   type_idx = d.format[2][0]
                   if name_idx != -1 :self._connect_ref(i, stringids, name_idx)
                   if type_idx != -1 :self._connect_ref(i, typeids, type_idx)
                elif bcode_value == dvm.DBG_START_LOCAL_EXTENDED:
                   name_idx = d.format[1][0]
                   type_idx = d.format[2][0]
                   sig_idx  = d.format[3][0]
                   if name_idx != -1 :self._connect_ref(i, stringids, name_idx)
                   if sig_idx != -1  :self._connect_ref(i, stringids, sig_idx)
                   if type_idx != -1 :self._connect_ref(i, typeids, type_idx)
                elif bcode_value == dvm.DBG_SET_FILE:
                   str_idx = d.format[0][0]
                   if str_idx != -1 :self._connect_ref(i, stringids, str_idx)
     
        # field_id
        fieldids = getattr(self, dvm.TYPE_MAP_ITEM[0x0004])
        for i in fieldids:
            self._connect_ref(i, typeids,   i.obj.class_idx)
            self._connect_ref(i, typeids,   i.obj.type_idx)
            self._connect_ref(i, stringids, i.obj.name_idx)

        typelists = getattr(self, dvm.TYPE_MAP_ITEM[0x1001])
        # add type_idx in type_item
        for k in typelists.keys():
            i  = typelists[k]
            for idx in range(0, i.obj.size):
                self._connect_ref(i, typeids, i.obj.list[idx].type_idx)

        # proto_id
        protoids = getattr(self, dvm.TYPE_MAP_ITEM[0x0003])
        for i in protoids:
            self._connect_ref(i, stringids, i.obj.shorty_idx)
            self._connect_ref(i, typeids,   i.obj.return_type_idx)
            if i.obj.parameters_off != 0:
               self._connect_ref(i, typelists, i.obj.parameters_off)

        # method_id
        methodids = getattr(self, dvm.TYPE_MAP_ITEM[0x0005])
        for i in methodids:
            self._connect_ref(i, typeids,   i.obj.class_idx)
            self._connect_ref(i, protoids,  i.obj.proto_idx)
            self._connect_ref(i, stringids, i.obj.name_idx)

        annitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2004])
        # -> encoded_annotation -> type_idx
        #    annotation_element -> name_idx
        for k in annitems.keys():
            i = annitems[k]
            self._connect_encoded_annotation(i, i.obj.annotation, stringids, typeids, fieldids, methodids)

        annsetitems = getattr(self, dvm.TYPE_MAP_ITEM[0x1003])
        # link to annotation_item
        # annotation_off_item
        for k in annsetitems.keys():
            i = annsetitems[k]
            entries = i.obj.annotation_off_item
            for idx in range(0, i.obj.size):
                self._connect_ref(i, annitems, entries[idx].annotation_off)

        ann_ref_sets = getattr(self, dvm.TYPE_MAP_ITEM[0x1002])
        # annotation_set_ref_list
        # link to annotation_item
        # annotation_off_item
        for k in ann_ref_sets.keys():
            i = ann_ref_sets[k]
            ls = i.obj.list
            for idx in range(0, i.obj.size):
                self._connect_ref(i, annsetitems,  ls[i.obj.annotations_off])

        encodearraryitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2005])
        # encoded array items
        for k in encodearraryitems.keys():
            i = encodearraryitems[k]
            obj = i.obj
            self._connect_encoded_array_item(i, obj.get_value() ,stringids, fieldids, methodids, typeids)

        codeitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2001])
        # debug_info_off
        # encoded_catch_handler_list->encoded_catch_handler
        #                             ->encoded_type_addr_pair
        #                               ->type_idx
        for k in codeitems.keys():
            i = codeitems[k]
            if int(i.obj.debug_info_off) > 0:
               self._connect_ref(i, debuginfos,  int(i.obj.debug_info_off))


            ins = i.obj.code.get_instructions()
            nb = 0
            for x in ins:
                if not hasattr(x, "get_kind"):
                   continue
 
                kd = x.get_kind() 

                if kd == dvm.KIND_METH:
                   self._connect_ref(i, methodids, x.get_ref_kind())
                elif kd == dvm.KIND_STRING:
                   self._connect_ref(i, stringids, x.get_ref_kind())
                elif kd == dvm.KIND_FIELD:
                   self._connect_ref(i, fieldids, x.get_ref_kind())
                elif kd == dvm.KIND_TYPE:
                   if x.get_ref_kind() > len(typeids):
                      continue

                   self._connect_ref(i, typeids, x.get_ref_kind())
                   if x.get_name() == "new-array":
                      # This is a special case, with new-arrary, the type
                      # would point to "[className" type, which implicitly
                      # points to className
                      type_str = stringdatas[stringids[typeids[x.get_ref_kind()].obj.descriptor_idx].obj.string_data_off].obj.get()
                      type_str = type_str[1:]
                      for ti, val in enumerate(typeids):
                          if type_str == stringdatas[stringids[val.obj.descriptor_idx].obj.string_data_off].obj.get():
                             self._connect_ref(i, typeids, ti)
                nb += 1

            if i.obj.tries_size > 0:
               for handlers in i.obj.get_handlers().get_list():
                   for x in handlers.get_handlers():
                       self._connect_ref(i, typeids, x.get_type_idx())

        classdatas = getattr(self, dvm.TYPE_MAP_ITEM[0x2000])
        # encoded_field->field_idx_diff
        # encoded_method->method_idx_diff
        #               ->code_off
        for k in classdatas.keys():
            i = classdatas[k]
            def connect_ref_f(size, obj, idx):
                for idx in range(0, size):
                    self._connect_ref(i, fieldids,  int(obj[idx].field_idx))

            def connect_ref_m(size, obj, idx):
                for idx in range(0, size):
                    self._connect_ref(i, methodids,  int(obj[idx].method_idx))
                    if int(obj[idx].code_off) != 0:
                       self._connect_ref(i, codeitems,  int(obj[idx].code_off))
         
            connect_ref_f(i.obj.static_fields_size,   i.obj.static_fields,   idx) 
            connect_ref_f(i.obj.instance_fields_size, i.obj.instance_fields, idx) 
            connect_ref_m(i.obj.direct_methods_size,  i.obj.direct_methods,  idx) 
            connect_ref_m(i.obj.virtual_methods_size, i.obj.virtual_methods, idx) 

        anndicitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2006])
        # class_annotations annotation_set_item
        # field_annotations -> field_idx (field_ids)
        #                   -> annotations_off (annotation_set_item)
        # method_annotations -> method_idx(method_ids)
        #                   -> annotations_off (annotation_set_item)
        # parameter_annotations -> method_idx(method_ids)
        #                   -> annotations_off (annotation_set_item)
        for k in anndicitems.keys():
            i = anndicitems[k]
            if i.obj.class_annotations_off:
               self._connect_ref(i, annsetitems, i.obj.class_annotations_off)

            def connect_ref_ann(size, target, obj, idx, field_name):
                for idx in range (0, size):
                     self._connect_ref(i, target, getattr(obj[idx], field_name))
                     self._connect_ref(i, annsetitems, obj[idx].annotations_off)

            connect_ref_ann(i.obj.annotated_fields_size, fieldids, i.obj.field_annotations, idx, "field_idx")
            connect_ref_ann(i.obj.annotated_methods_size, methodids, i.obj.method_annotations, idx, "method_idx")
            connect_ref_ann(i.obj.annotated_parameters_size, methodids, i.obj.parameter_annotations, idx, "method_idx")

        # classdefs
        classdefs = getattr(self, dvm.TYPE_MAP_ITEM[0x0006])
        for i in classdefs:
            self._connect_ref(i, typeids,   i.obj.class_idx)
            self._connect_ref(i, typeids,   i.obj.superclass_idx)
          
            if i.obj.source_file_idx != 0xffffffff:
               self._connect_ref(i, stringids, i.obj.source_file_idx)

            if i.obj.interfaces_off != 0:
               self._connect_ref(i, typelists, i.obj.interfaces_off)

            if i.obj.annotations_off != 0:
               self._connect_ref(i, anndicitems, i.obj.annotations_off)

            if i.obj.class_data_off != 0:
               self._connect_ref(i, classdatas, i.obj.class_data_off)

            if i.obj.static_values_off != 0:
               self._connect_ref(i, encodearraryitems,  i.obj.static_values_off)

    def _walk(self, i, op, indent, op_obj, parent = None, ret = 0):
        indent += 1
        ret_1 = op(i, indent, op_obj, parent, ret)
        for x in i.child:
            self._walk(x, op, indent, op_obj, i, ret_1)
        indent -= 1

    def _build_refcount(self):
        # The start point is always classdefs
        classdefs = getattr(self, dvm.TYPE_MAP_ITEM[0x0006])
        def op(obj, i, o_o, p, ret):
             obj.ref_count += 1
             obj.class_node = o_o
             return ret

        for i in classdefs:
            self._walk(i, op, 0, i, 0)

        return 0

    def _output_statistics(self):
        def sum_up(item):
            result = [0]
            def op_s(obj, i, ref, p, r):
                ref[0] += obj.size/float(max(obj.ref_count,1))
                return r 

            self._walk(item, op_s, 0, result)
            item.cum = result[0]

        def print_i(item, item_list):
            p = printer.Dex_printer()

            if isinstance(item.obj, dvm.ClassDefItem):
               sum_up(item)
               col1, col2 = p.Print(item.obj)
               item_list.append([col1, item.cum, item.size, col2, ""])

               for i in item.child:
                   if isinstance(i.obj, dvm.ClassDataItem):
                      code_dic = {}
                      for dm in  i.obj.get_direct_methods():
                          code_dic[dm.get_code_off()] = dm.get_name()

                      for dm in  i.obj.get_virtual_methods():
                          code_dic[dm.get_code_off()] = dm.get_name()

                      for x in i.child: 
                          # Find all the methods
                          if isinstance(x.obj, dvm.DalvikCode):
                             sum_up(x)
                             item_list.append(["Method", x.cum, x.size, col2, code_dic[x.obj.get_off()]])
 
            elif (isinstance(item.obj, dvm.DalvikCode) or
                  isinstance(item.obj, dvm.StringIdItem) or
                  isinstance(item.obj, dvm.MethodIdItem) or
                  isinstance(item.obj, dvm.FieldIdItem) or
                  isinstance(item.obj, dvm.TypeList) or
                  isinstance(item.obj, dvm.MapList) or
                  isinstance(item.obj, dvm.ClassDataItem)):
                 pass
            else:
               sum_up(item)
               idx = 0
               if (isinstance(item.obj, dvm.StringDataItem)):
                    idx = item.parent.idx
               else:
                    idx = item.idx

               col1, col2 = p.Print(item.obj, idx)

               class_name = p.Print(item.class_node.obj)[1] if item.ref_count == 1 else "many"
               item_list.append([col1, item.cum, item.size, class_name, col2])

        item_list = []

        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            obj_set = getattr(self, name)
            if k >= 0x1000:
               for ok in obj_set.keys():
                   item = obj_set[ok]
                   print_i(item, item_list)
            else:
               for item in obj_set:
                   print_i(item, item_list)

        fmt_str = "{0:<20}{1:<10}{2:<10}{3:<60}{4}"
 
        print "\033c"
        print fmt_str.format("Type", "Cum.", "Self",  "Content", "Class")

        if len(sys.argv) == 3 and sys.argv[2] == "-s":
           item_list = sorted(item_list, key = lambda x:-x[2])
        else:
           item_list = sorted(item_list, key = lambda x:-x[1])

        for i in item_list:
            print fmt_str.format(i[0], int(i[1]), int(i[2]), i[4][:50], i[3])

    def _unreferenced_check(self):
        # Inspect unreferenced the item list 
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]

            if (name == "TYPE_MAP_LIST" or
                name == "TYPE_HEADER_ITEM" or
                name == "TYPE_CLASS_DEF_ITEM"):
               continue

            s = 0
            found = False
            if k >= 0x1000:
               for kt in getattr(self, name).keys():
                   obj = getattr(self, name)[kt]
                   if obj.ref_count == 0:
                      print obj.obj, obj.obj.offset
                      found = True
                      obj.obj.show()
            else:
               for i in getattr(self, name):
                   if i.ref_count == 0:
                      print "---Unreferenced Object ---"
                      print i.obj, i.obj.offset
                      found = True
                      i.obj.show()

            #assert(not found and "BUG! must have no unreferenced item")

    def _inspect_map(self):
        a_s = 0
        # Inspect the item list 
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            s = 0
            if k >= 0x1000:
               for kt in getattr(self, name).keys():
                   s += getattr(self, name)[kt].size
               print name,s
            else:
               for i in getattr(self, name):
                    s += i.size
               print name ,s
   
            a_s += s

        print a_s

dex = Dex(sys.argv[1])
dex.analyze()
