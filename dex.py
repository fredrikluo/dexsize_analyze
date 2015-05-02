import dvm

class Dex(object):

    class MapListItemAccessor(object):
        def __init__(self, obj):
            self.obj = obj

        def get_obj(self):
            if type(self.obj) is list:
               return self.obj

            if type(self.obj) is dvm.HeaderItem or type(self.obj) is dvm.MapList:
               return [self.obj]

            if hasattr(self.obj, "get_obj"):
               return self.obj.get_obj()

            return [] 

    def __init__(self,filename):
        if filename == None: 
            raise(Exception("Null File Name."))        

        self._dex = dvm.DalvikVMFormat(open(filename).read(), 'rb')

        # All the items in the Dex file
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            setattr(self, name, {} if k >= 0x1000 else [])

        # Build the map
        self._build_map()

        # Build the reference map
        self._build_reference_map()

        # Build the reference count
        self._build_refcount()

        a_s = 0
        # Inspect the item list 
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            s = 0
            if k >= 0x1000:
               for kt in getattr(self, name).keys():
                   s += getattr(self, name)[kt][1]
               print name,s
            else:
               for i in getattr(self, name):
                    s += i[1]
               print name ,s
   
            a_s += s

        print a_s

    def _build_map(self):
        for k in dvm.TYPE_MAP_ITEM.keys():
            name = dvm.TYPE_MAP_ITEM[k]
            obj_ls =  self.MapListItemAccessor(self._dex.map_list.get_item_type( name )).get_obj()
            for obj in obj_ls:
                if k >= 0x1000:
                   getattr(self, name)[obj.get_off()] = [obj, obj.meta_size, [], 0]
                else:
                   getattr(self, name).append([obj, obj.meta_size, [], 0])

    def _connect_ref(self, ls, target, target_idx):
        ls[2].append(target[target_idx])
        target[target_idx][3] = 1

    def _build_reference_map(self):
        # header has no reference items
        # maplists = dvm.TYPE_MAP_ITEM[0x1000]
        # ingore the map list for now

        # Node with no reference to others
        stringdatas = getattr(self, dvm.TYPE_MAP_ITEM[0x2002])
        encodearraryitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2005])
        debuginfos = getattr(self, dvm.TYPE_MAP_ITEM[0x2003])

        # string_id
        stringids = getattr(self, dvm.TYPE_MAP_ITEM[0x0001])
        for i in stringids:
            self._connect_ref(i, stringdatas, i[0].string_data_off)
     
        # type_id
        typeids = getattr(self, dvm.TYPE_MAP_ITEM[0x0002])
        for i in typeids:
            self._connect_ref(i, stringids, i[0].descriptor_idx)

        # field_id
        fieldids = getattr(self, dvm.TYPE_MAP_ITEM[0x0004])
        for i in fieldids:
            self._connect_ref(i, typeids,   i[0].class_idx)
            self._connect_ref(i, typeids,   i[0].type_idx)
            self._connect_ref(i, stringids, i[0].name_idx)

        typelists = getattr(self, dvm.TYPE_MAP_ITEM[0x1001])
        # add type_idx in type_item
        for k in typelists.keys():
            i  = typelists[k]
            for idx in range(0, i[0].size):
                self._connect_ref(i, typeids, i[0].list[idx].type_idx)

        # proto_id
        protoids = getattr(self, dvm.TYPE_MAP_ITEM[0x0003])
        for i in protoids:
            self._connect_ref(i, stringids, i[0].shorty_idx)
            self._connect_ref(i, typeids,   i[0].return_type_idx)
            if i[0].parameters_off != 0:
               self._connect_ref(i, typelists, i[0].parameters_off)

        # method_id
        methodids = getattr(self, dvm.TYPE_MAP_ITEM[0x0005])
        for i in methodids:
            self._connect_ref(i, typeids,   i[0].class_idx)
            self._connect_ref(i, protoids,  i[0].proto_idx)
            self._connect_ref(i, stringids, i[0].name_idx)

        annitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2004])
        # -> encoded_annotation -> type_idx
        #    annotation_element -> name_idx
        for k in annitems.keys():
            i = annitems[k]
            obj = i[0].annotation
            self._connect_ref(i, typeids,   int(obj.type_idx))
            for idx in range (0, int(obj.size)):
                self._connect_ref(i, stringids,  int(obj.elements[idx].name_idx))

        annsetitems = getattr(self, dvm.TYPE_MAP_ITEM[0x1003])
        # link to annotation_item
        # annotation_off_item
        for k in annsetitems.keys():
            i = annsetitems[k]
            entries = i[0].annotation_off_item
            for idx in range(0, i[0].size):
                self._connect_ref(i, annitems, entries[idx].annotation_off)

        ann_ref_sets = getattr(self, dvm.TYPE_MAP_ITEM[0x1002])
        # annotation_set_ref_list
        # link to annotation_item
        # annotation_off_item
        for k in ann_ref_sets.keys():
            i = ann_ref_sets[k]
            ls = i[0].list
            for idx in range(0, i[0].size):
                self._connect_ref(i, annsetitems,  ls[i[0].annotations_off])

        codeitems = getattr(self, dvm.TYPE_MAP_ITEM[0x2001])
        # debug_info_off
        # encoded_catch_handler_list->encoded_catch_handler
        #                             ->encoded_type_addr_pair
        #                               ->type_idx
        for k in codeitems.keys():
            i = codeitems[k]
            if int(i[0].debug_info_off) > 0:
               self._connect_ref(i, debuginfos,  int(i[0].debug_info_off))

            # Disassemble the code and find the references from the code
            #print "--Dissemble the code"
            #for x in range(0, i[0].insns_size):
            #    print i[0].insns[x]

            # TODO: Link the catch hanlder to type_idx
            #if i[0].tries_size > 0:

        classdatas = getattr(self, dvm.TYPE_MAP_ITEM[0x2000])
        # encoded_field->field_idx_diff
        # encoded_method->method_idx_diff
        #               ->code_off
        for k in classdatas.keys():
            i = classdatas[k]
            def connect_ref_f(size, obj, idx):
                for idx in range(0, size):
                    self._connect_ref(i, fieldids,  int(obj[idx].field_idx_diff))

            def connect_ref_m(size, obj, idx):
                for idx in range(0, size):
                    self._connect_ref(i, methodids,  int(obj[idx].method_idx_diff))
                    if int(obj[idx].code_off) != 0:
                       self._connect_ref(i, codeitems,  int(obj[idx].code_off))
          
            connect_ref_f(i[0].static_fields_size,   i[0].static_fields,   idx) 
            connect_ref_f(i[0].instance_fields_size, i[0].instance_fields, idx) 
            connect_ref_m(i[0].direct_methods_size,  i[0].direct_methods,  idx) 
            connect_ref_m(i[0].virtual_methods_size, i[0].virtual_methods, idx) 

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
            self._connect_ref(i, annsetitems, i[0].class_annotations_off)

            def connect_ref_ann(size, target, obj, idx):
                for idx in range (0, size):
                     self._connect_ref(i, target, obj[idx])

            connect_ref_ann(i[0].annotated_fields_size, fieldids, i[0].field_annotations, idx)
            connect_ref_ann(i[0].annotated_methods_size, methodids, i[0].method_annotations, idx)
            connect_ref_ann(i[0].annotated_parameters_size, methodids, i[0].parameter_annotations, idx)

        # classdefs
        classdefs = getattr(self, dvm.TYPE_MAP_ITEM[0x0006])
        for i in classdefs:
            self._connect_ref(i, typeids,   i[0].class_idx)
            self._connect_ref(i, typeids,   i[0].superclass_idx)

            if i[0].source_file_idx != 0xffffffff:
               self._connect_ref(i, stringids, i[0].source_file_idx)

            if i[0].interfaces_off != 0:
               self._connect_ref(i, typelists, i[0].interfaces_off)

            if i[0].annotations_off != 0:
               self._connect_ref(i, anndicitems, i[0].annotations_off)

            if i[0].class_data_off != 0:
               self._connect_ref(i, classdatas, i[0].class_data_off)

            if i[0].static_values_off != 0:
               self._connect_ref(i, encodearraryitems,  i[0].static_values_off)

        return 0

    def _walk(self, i, op, indent, op_obj):
        indent += 1
        op(i, indent, op_obj)
        for x in i[2]:
            self._walk(x, op, indent, op_obj)
        indent -= 1

    def _build_refcount(self):
        # The start point is always classdefs
        classdefs = getattr(self, dvm.TYPE_MAP_ITEM[0x0006])

        def op(obj, indent, op_obj):
            obj[3] += 1

        for i in classdefs:
            self._walk(i, op, 0, 0)

    def analyze(self):
        # Walk through the class list
        classdefs = getattr(self, dvm.TYPE_MAP_ITEM[0x0006])

        a_list = []
        a_sum = 0
        for i in classdefs:
            #print "Start dumping class", i[0]
            ref_class = []

            def op(obj, indent, ref_class):
                ref_class.append([obj, indent])

            self._walk(i, op, 0, ref_class)

            #Sum all the value
            _sum = 0.0
            for item in ref_class:
                ls, indent = item[0], item[1]
                a_list.append(ls[0])
                size = ls[1]/float(ls[3] if ls[3] > 0 else 1)
                print " " * indent, ls[0], ls[1], ls[3], size
                if type(ls[0]) is dvm.DalvikCode:
                   ls[0].show()
                _sum += size

            a_sum += _sum
            print "Sum is:", _sum

        #print "Total:", a_sum

        def make_unique(original_list):
            unique_list = []
            [unique_list.append(obj) for obj in original_list if obj not in unique_list]
            return unique_list

        #print "start"
        #print "Sum2:", sum([x.meta.size for x in make_unique(a_list)])
        #print a_list


dex = Dex("./classes.dex")
dex.analyze()

