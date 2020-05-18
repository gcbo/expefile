import pefile
import struct
class PE(pefile.PE):
    def __init__(self, *argl, **argd):
        pefile.PE.__init__(self, *argl, **argd)
        self.__data__ =bytearray(self.__data__)
        self.new_dll = {}
        self.exist_dll ={}
        self.new_relocs={}
        self.get_dll()
    def get_dll(self):
        self.exist_dll={}
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            self.exist_dll[entry.dll]=[ imp.name for imp in  entry.imports ]
    def copy_to_raw(self,raw,data):
        for d in data:
            self.__data__[raw] = d
            raw +=1
        return  True
    def copy_to_rva(self,rva,data):
            return  self.copy_to_raw(self.get_offset_from_rva(rva),data)
    def add_section(self,name,rva,size,Characteristics=None):
        ## 能在section header 中添加 header 项，而不会 超过 第二个section ,因为section header 项在第一个section中
        sec_list = self.sections
        sorted(sec_list,key=lambda x: x.PointerToRawData )
        for sec in sec_list:
            if sec.PointerToRawData !=0:
                first_sec_end_raw_addr=sec.PointerToRawData
                break
        if self.sections[-1].__file_offset__ +  2*self.sections[-1].sizeof() > first_sec_end_raw_addr:
            print("can't add section header entry in section header")
            return  False
        last_sec_end_rva_addr = self.sections[-1].VirtualAddress + self.sections[-1].SizeOfRawData
        if rva < last_sec_end_rva_addr:
            print("rva address is smaller than  last section end rva ")
            return False
        else:
            # 构造 section header entry
            new_sec = pefile.SectionStructure(self.__IMAGE_SECTION_HEADER_format__,pe=self)
            new_sec_raw_start_addr = self.sections[-1].get_file_offset()+self.sections[-1].sizeof()
            new_sec.set_file_offset(new_sec_raw_start_addr)
            if len(name ) >8 :
                print("name too long")
                return False
            else:
                name = name + (8-len(name))*b"\x00"
            # 设置 Name
            new_sec.Name = name
            # rva 要对齐
            if rva % self.OPTIONAL_HEADER.SectionAlignment :
                print(f"rva is not a multiple of SectionAlignment {self.OPTIONAL_HEADER.SectionAlignment} ")
                new_sec.VirtualAddress = (int(rva/self.OPTIONAL_HEADER.SectionAlignment)+1 ) * self.OPTIONAL_HEADER.SectionAlignment
            else:
                new_sec.VirtualAddress = rva
            # 设置 start rva
            # new_sec.VirtualAddress = rva
            new_sec.Misc_VirtualSize = new_sec.Misc = new_sec.Misc_PhysicalAddress = size
            #  size 要符合 file 对齐
            if size % self.OPTIONAL_HEADER.FileAlignment :
                print(f"rva is not a multiple of SectionAlignment {self.OPTIONAL_HEADER.FileAlignment} ")
                new_sec.SizeOfRawData =  (int(size/self.OPTIONAL_HEADER.FileAlignment)+1 ) * self.OPTIONAL_HEADER.FileAlignment
            else:
                new_sec.SizeOfRawData = size
            # start raw addr
            new_sec.PointerToRawData = self.sections[-1].PointerToRawData + self.sections[-1].SizeOfRawData
            new_sec.PointerToRelocations=new_sec.PointerToLinenumbers=new_sec.NumberOfRelocations=new_sec.NumberOfLinenumbers=0
            if Characteristics == None:
                new_sec.Characteristics = 0xe0000020
            self.FILE_HEADER.NumberOfSections = self.FILE_HEADER.NumberOfSections + 1
            sec_header_entry = new_sec.__pack__()
            self.__data__ = self.__data__ + new_sec.SizeOfRawData*b'\x00'
            self.copy_to_raw(new_sec_raw_start_addr,sec_header_entry)
            self.parse_sections(self.sections[0].get_file_offset())
            return True
    def reset_checksum(self):
        size = self.sections[-1].VirtualAddress + self.sections[-1].SizeOfRawData
        if size % self.OPTIONAL_HEADER.SectionAlignment :
            size = int(size/ self.OPTIONAL_HEADER.SectionAlignment ) *  self.OPTIONAL_HEADER.SectionAlignment
        self.OPTIONAL_HEADER.SizeOfImage = size
        checksum = self.generate_checksum()
        self.OPTIONAL_HEADER.CheckSum = checksum

    def generate_imps(self,rva):
        """从rva开始内存中数据的顺序
         IID + INT + IAT + dll_name  + hint_name_table """
        new_imp_descs = b''
        INT_data = b''
        IAT_data = b''
        dll_name = b''
        hint_name_table = b''

        new_imp_begin_rva = rva + len(self.DIRECTORY_ENTRY_IMPORT) * 0x14
        INT_begin_rva = rva + (len(self.DIRECTORY_ENTRY_IMPORT) + len(self.new_dll) +1)* 0x14

        imps_len = 0
        dll_name_len = 0
        for dll in self.new_dll:
            imps_len = imps_len + (1+len(self.new_dll[dll]))*4
            dll_name_len = len(dll) + 1 + dll_name_len

        IAT_begin_rva = INT_begin_rva + imps_len
        dll_name_rva = IAT_begin_rva + imps_len
        hint_name_table_rva = dll_name_rva + dll_name_len
        for i, name in enumerate(self.new_dll):
            new_imp_desc =  pefile.Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__)
            # name rva
            new_imp_desc.Name = dll_name_rva
            # INT rva
            new_imp_desc.OriginalFirstThunk = INT_begin_rva
            # IAT rva
            new_imp_desc.FirstThunk = IAT_begin_rva

            new_imp_desc.TimeDateStamp =new_imp_desc.ForwarderChain = 0
            for j,imp in enumerate(self.new_dll[name]):
                INT_data += struct.pack("<i",hint_name_table_rva)
                IAT_data += struct.pack("<i",hint_name_table_rva)
                INT_begin_rva +=4
                IAT_begin_rva +=4
                imp_data =   2* b'\x00' + imp + b'\x00'
                hint_name_table += imp_data
                hint_name_table_rva += len(imp_data)
            # end of IAT and INT
            INT_data += 4*b'\x00'
            IAT_data += 4 * b'\x00'
            INT_begin_rva += 4
            IAT_begin_rva += 4
            dll_name = dll_name +  name + b'\x00'
            dll_name_rva += len(name+b'\x00')
            new_imp_descs  += new_imp_desc.__pack__()

        null_imp_desc  = pefile.Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__)
        null_imp_desc.OriginalFirstThunk = null_imp_desc.Characteristics = 0
        null_imp_desc.TimeDateStamp = null_imp_desc.FirstThunk = null_imp_desc.ForwarderChain = null_imp_desc.Name = 0
        new_imp_descs += null_imp_desc.__pack__()

        old_imp_descs = self.get_data(self.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress,self.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size-0x14)
        together = old_imp_descs + new_imp_descs
        together = together + INT_data +IAT_data + dll_name + hint_name_table
        return  together

    def add_imps(self,rva,data):

        self.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = rva
        self.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = (len(self.DIRECTORY_ENTRY_IMPORT)+len(self.new_dll)+1) * 0x14
        self.copy_to_rva(rva,data)
        self.parse_data_directories()
        self.reset_checksum()


    def get_secion_by_name(self,name):
        name = name + b'\x00' * (8-len(name))
        for sec in self.sections:
            if sec.Name == name :
                return  sec
        return False
    def add_imp_fun(self,dll_name,imp_fun_name):
        # 检查是否已经存在dll 和 导入函数
        if dll_name in self.exist_dll:
            return
        if dll_name not in self.new_dll:
            self.new_dll[dll_name]  = []
            self.new_dll[dll_name].append(imp_fun_name)
        else:
            if imp_fun_name not in self.new_dll[dll_name]:
                self.new_dll[dll_name].append(imp_fun_name)

    def resize_sec(self,sec_name,size):
        sec_name = sec_name + b'\x00' * (8-len(name))
        if sec_name == self.sections[-1].Name:
            self.sections[-1].SizeOfRawData +=size
            # self.sections[-1].Misc_PhysicalAddress +=size
            if size >=0 :
                self.__data__ += size*b'\x00'
            else:
                self.__data__ = self.__data__[:size]
        else:
            print("cant resize")

    def get_new_section_rva(self):

        rva = self.sections[-1].VirtualAddress+self.sections[-1].SizeOfRawData
        return (int(rva / self.OPTIONAL_HEADER.SectionAlignment) + 1) * self.OPTIONAL_HEADER.SectionAlignment



    def add_imps_to_sec(self,sec_name,rva):
        sec = self.get_secion_by_name(sec_name)
        if sec == False :
            print(f"{sec_name} dont exist")
            imps_data = self.generate_imps(rva)
            print("add it")
            self.add_section(sec_name,rva,len(imps_data))
        else:
            imps_data = self.generate_imps(rva)
        self.add_imps(rva, imps_data)
        return len(imps_data)

    def get_imp_from_name(self,name):
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name == name:
                    return  imp
        return False


    def add_reloc(self,rva):
        if not self.has_relocs():
            return False
        base_rva = rva>>12<<12
        relco_data = rva - base_rva
        if base_rva in self.new_relocs:
            self.new_relocs[base_rva].append(relco_data)
        else:
            self.new_relocs[base_rva] = [relco_data]
        return  True
    def generate_relocs(self):
        ''' 一些call，jmp是用绝对地址跳转，如常见变量访问，以及调用IAT,需要重定位,需要指明重定位的rva'''
        '''一般重定位的内容是dword，而且是va(相对于imagebase)'''
        new_relocs = b''
        for base_rva in self.new_relocs:
            base_rva_data = struct.pack('<i',base_rva)
            data_size = struct.pack('<i',len(self.new_relocs[base_rva])*2+8)

            entries = b''

            for reloc_data in self.new_relocs[base_rva]:
                entry =( 3<<12 ) + reloc_data
                entries+=struct.pack('<H',entry)
            new_relocs =new_relocs  + base_rva_data +data_size + entries
        return  new_relocs
    def add_relocs_to_sec(self):
        reloc_sec_rva =  self.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress
        new_reloc_rva =  self.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress +  self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
        reloc_data = self.generate_relocs()
        relocs_size =  self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size + len(reloc_data)
        self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = relocs_size
        self.copy_to_rva(new_reloc_rva,reloc_data)
        self.parse_data_directories()





# add section
# add imps
# write
#