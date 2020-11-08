# -*-coding:utf-8-*-
import sys
import struct

class PEParser(object):
    def __init__(self,file_path):
        self.path = file_path
        self.data =  ""   # store all of the content of PE file

        self.VA = 0 # vritual memory address
        self.RVA = 0 # relative virtual memory address
        self.FOA = 0 # pe file offset address

        # IMAGE_DOS_HEADER
        self.e_lfanew =  0   # file address of new exe file header

        # IMAGE_FILE_HEADER
        self.FileHeader = {"Machine": 0, "NumberOfSection": -1, "TimeDataStamp": -1, \
                           "PointerToSymbolTable": -1, "SizeOfOptionalHeader": -1, \
                           "NumberOfSymbols": -1, "Characteristics": -1}
        self.OptionalHeader_FOA = 0

        # IMAGE_OPTIONAL_HEADER
        self.optionalheader32 = {"magicword": -1, "majorlinkerver": -1, "minorlinkerver": -1, \
                               "sizeofcode": -1, "sizeofinitializeddata": -1, "sizeofuninitializeddata": -1, \
                               "addressofentrypoint": -1, "baseofcode": -1, "baseofdata": -1, \
                               "imagebase": -1, "sectionalignment": -1, "filealignment": -1, \
                               "majoroperationsystemver": -1, "minoroperatingsystemver": -1, "majorimagever": -1, \
                               "majorsubsystemver": -1, "minorimagever": -1, "minorsubsystemver": -1, \
                               "win32ver": -1, "sizeofimage": -1, "sizeofheaders": -1, \
                               "checksum": -1, "subsystem": -1, "dllcharacteristics": -1, \
                               "sizeofstackreverse": -1, "sizeofstackcommit": -1, "sizeofheapreverse": -1, \
                               "sizeofheapcommit": -1, "loaderflags": -1, "numberofrvaandsizes": -1, \
                               }
        # DataDirectory
        self.DataDirectory = {"Export_VirutalAddress": -1, "Export_isize": -1, \
                              "Import_VirtualAddress": -1, "Import_isize": -1, \
                              "Resource_VirtualAddress": -1, "Resource_isize": -1, \
                              "Exception_VirtualAddress": -1, "Exception_isize": -1, \
                              "Certificate_VirtualAddress": -1, "Certificate_isize": -1, \
                              "Relocation_VirtualAddress": -1, "Relocation_isize": -1, \
                              "Debug_VirtualAddress": -1, "Debug_isize": -1, \
                              "Architecture_VirtualAddress": -1, "Architecture_isize": -1, \
                              "Global_Ptr_VirtualAddress": -1, "Global_Ptr_isize": -1, \
                              "TLS_VirtualAddress": -1, "TLS_isize": -1, \
                              "Load_Config_VirtualAddress": -1, "Load_Config_isize": -1, \
                              "Bound_Import_VirtualAddress": -1, "Bound_Import_isize": -1, \
                              "IAT_VirtualAddress": -1, "IAT_isize": -1, \
                              "Delay_Import_VirtualAddress": -1, "Delay_Import_isize": -1, \
                              "CLR_VirtualAddress": -1, "CLR_isize": -1, \
                              "Reserved_VirtualAddress": -1, "Reserved_isize": -1, \
                              }

        # IMAGE_SECTION_HEADER
        self.Section_Header_FOA = 0
        self.SectionHeader = {"name": "name", "Misc_PhysicalAddress_or_VirtualSize": -1, \
                              "VirtualAddress": -1, "SizeOfRawData": -1, "PointerToRawData": -1, \
                              "PointerToRelocations": -1, "PointerToLinenumbers": -1, \
                              "NumberOfRelocations": -1, "NumberOfLinenumbers": -1, "Characteristics": -1}
        self.SectionHeaders = {}

        self.parsed_PE = 0
        self.analysed_import_descriptor = 0
        self.analysed_thunk_data = 0

        # IID represent IMAGE_IMPORT_DESCRIPTOR
        self.IIDs = {}

        # every name in IIDs has a ThunkData structure
        self.ThunkData = {}
        self.import_by_names = {}

    def parse_PE(self):
        """ parse PE, store all data structure of PE """
        self.data = self.read_data_from_file()     # store all of the content of PE file

        # parse DOS header
        self.e_lfanew = self.get_e_lfanew()

        # parse file header
        ret_FileHeader = self.get_file_header()
        for key in self.FileHeader:
            self.FileHeader[key] = ret_FileHeader[key]
            print(key," 0x{:x}".format(self.FileHeader[key]))

        # parse optional header
        print("")
        self.OptionalHeader_FOA = self.FOA + 0x18
        ret_OptionalHeader32 = self.get_optional_header32()
        for key in self.optionalheader32:
            self.optionalheader32[key] = ret_OptionalHeader32[key]
            print(key," 0x{:x}".format(self.optionalheader32[key]))

        # parse data directory, where define index of different type data，such as import table, export table, Resource table, Relocation table
        print("")
        ret_DataDirectory = self.get_data_directory()
        for key in self.DataDirectory:
            self.DataDirectory[key] = ret_DataDirectory[key]
            print(key," 0x{:x}".format(self.DataDirectory[key]))

        # parse section header
        self.Section_Header_FOA = self.get_e_lfanew() + 0xf8
        print("")
        for i in range(self.FileHeader["NumberOfSection"]):
            ret_SectionHeader = self.get_section_header(i)
            self.SectionHeaders[ret_SectionHeader["name"]] = ret_SectionHeader
            print("name : {0}".format(self.SectionHeaders[ret_SectionHeader["name"]]["name"]))
            print("offset in the file: 0x{:x}".format(self.SectionHeaders[ret_SectionHeader["name"]]["PointerToRawData"]))
            print("size in the file: 0x{:x}".format(self.SectionHeaders[ret_SectionHeader["name"]]["SizeOfRawData"]))


    def analyse_import_descriptor(self):
        if not self.parsed_PE:
            self.parse_PE()
            self.pased_PE = 1
        rva = self.DataDirectory["Import_VirtualAddress"]
        foa = self.RVA_to_FOA(rva)
        # IID represent IMAGE_IMPORT_DESCRIPTOR
        IID = {"OriginalFirstThunk": -1,\
               "TimeDataStamp": -1,\
               "ForwarderChain": -1, \
               "Name1": -1, \
               "FirstThunk": -1\
               }
        base = foa
        offset = 0xc
        while struct.unpack("<L", self.data[base+offset:base+offset+4])[0]:
            offset = 0
            IID["OriginalFirstThunk"] =struct.unpack("<L", self.data[base+offset:base+offset+4])[0]
            #print(IID["OriginalFirstThunk"], end = ' ')
            offset = 4
            IID["TimeDataStamp"] =struct.unpack("<L", self.data[base+offset:base+offset+4])[0]
            offset = 8
            IID["ForwarderChain"] =struct.unpack("<L", self.data[base+offset:base+offset+4])[0]
            offset = 0xc
            IID["Name1"] =struct.unpack("<L", self.data[base+offset:base+offset+4])[0]
            offset = 0x10
            IID["FirstThunk"] =struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

            # name address
            name = self.get_str(self.RVA_to_FOA(IID["Name1"]))
            self.IIDs[name] = IID
            #print(base)
            IID = {}

            base += 0x14
            offset = 0xc

        print(self.IIDs)
        self.analysed_import_descriptor = 1

    def analyse_thunk_data(self):
        if not self.parsed_PE:
            self.parse_PE()
            self.parsed_PE = 1
        if not self.analysed_import_descriptor:
            self.analyse_import_descriptor()
            self.analysed_import_descriptor = 1

        ThunkData = []
        for name in self.IIDs:
            foa = self.RVA_to_FOA(self.IIDs[name]["OriginalFirstThunk"])
            print(name, 'is', self.IIDs[name]["OriginalFirstThunk"])
            base = foa
            offset = 0
            value = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]
            while value:
                ThunkData.append(value)
                offset += 4
                value = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]
            self.ThunkData[name] = ThunkData
            ThunkData = []
        print(self.ThunkData)
        print(" ")
        self.analysed_thunk_data = 1


    def analyse_import_by_name(self):
        if not self.parsed_PE:
            self.parse_PE()
            self.parsed_PE = 1
        if not self.analysed_import_descriptor:
            self.analyse_import_descriptor()
            self.analysed_import_descriptor = 1
        if not self.analysed_thunk_data:
            self.analyse_thunk_data()
            self.analysed_thunk_data = 1

        import_by_name = []
        import_by_names = []
        for name in self.ThunkData:
            print("-"*10, name, "-"*10)
            for element in self.ThunkData[name]:
                if element > 100000:
                    continue
                #print(element, end=' ')
                foa = self.RVA_to_FOA(element)
                base = foa
                offset = 0
                #print("{0}".format(foa))
                #import_by_name["Hint"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]
                offset = 2
                import_by_name = self.get_str(foa+offset)
                print(import_by_name)
                import_by_names.append(import_by_names)
            #print(import_by_names[0])
            self.import_by_names[name] = import_by_names
            print("-"*33)
            print(" ")
            #print(self.import_by_names)
        #print(self.import_by_names)

    def get_str(self, foa_addr):
        str = ""
        while self.data[foa_addr]:

            str += chr(self.data[foa_addr])
            foa_addr += 1
        return str


    def RVA_to_FOA(self, rva):
        if not self.parsed_PE:
            self.parse_PE()
            self.parsed_PE = 1
        FOAOfSection = 0
        # the section rva belong to, RVA of the sections
        for section_header_name in self.SectionHeaders:
            RVAOfSection_low = self.SectionHeaders[section_header_name]["VirtualAddress"]
            RVAOfSection_high = RVAOfSection_low + self.SectionHeaders[section_header_name]["Misc_PhysicalAddress_or_VirtualSize"]
            if rva >= RVAOfSection_low and rva <= RVAOfSection_high:
                FOAOfSection = self.SectionHeaders[section_header_name]["PointerToRawData"]
                break
        # foa_of_the_section + offset
        return FOAOfSection + (rva - RVAOfSection_low)

    def analyse_PE(self):
        self.parse_PE()
        pass

    def get_section_header(self, section_num):
        base = self.Section_Header_FOA + section_num*0x28
        offset = 0
        SectionHeader = {}
        SectionHeader["name"] = str(self.data[base+offset:base+offset+8])

        offset = 0x8
        SectionHeader["Misc_PhysicalAddress_or_VirtualSize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xc
        SectionHeader["VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x10
        SectionHeader["SizeOfRawData"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x14
        SectionHeader["PointerToRawData"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x18
        SectionHeader["PointerToRelocations"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x1c
        SectionHeader["PointerToLinenumbers"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x20
        SectionHeader["NumberOfRelocations"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]

        offset = 0x22
        SectionHeader["NumberOfLinenumbers"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]

        offset = 0x24
        SectionHeader["Characteristics"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        return SectionHeader


    def get_data_directory(self):
        base = self.get_e_lfanew()
        offset = 0x78
        DataDirectory = {}

        DataDirectory["Export_VirutalAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x7c
        DataDirectory["Export_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x80
        DataDirectory["Import_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x84
        DataDirectory["Import_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x88
        DataDirectory["Resource_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x8c
        DataDirectory["Resource_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x90
        DataDirectory["Exception_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x94
        DataDirectory["Exception_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x98
        DataDirectory["Certificate_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x9c
        DataDirectory["Certificate_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xa0
        DataDirectory["Relocation_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xa4
        DataDirectory["Relocation_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xa8
        DataDirectory["Debug_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xac
        DataDirectory["Debug_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xb0
        DataDirectory["Architecture_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xb4
        DataDirectory["Architecture_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xb8
        DataDirectory["Global_Ptr_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xbc
        DataDirectory["Global_Ptr_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xc0
        DataDirectory["TLS_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xc4
        DataDirectory["TLS_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xc8
        DataDirectory["Load_Config_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xcc
        DataDirectory["Load_Config_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xd0
        DataDirectory["Bound_Import_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xd4
        DataDirectory["Bound_Import_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xd8
        DataDirectory["IAT_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xdc
        DataDirectory["IAT_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xe0
        DataDirectory["Delay_Import_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xe4
        DataDirectory["Delay_Import_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xe8
        DataDirectory["CLR_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xec
        DataDirectory["CLR_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xf0
        DataDirectory["Reserved_VirtualAddress"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xf4
        DataDirectory["Reserved_isize"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        return DataDirectory

    def get_optional_header32(self):
        base = self.get_e_lfanew()
        offset = 0x18
        OptionalHeader32 = {}

        OptionalHeader32["magicword"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]

        offset = 0x1a
        OptionalHeader32["majorlinkerver"] = struct.unpack("<B", self.data[base+offset:base+offset+1])[0]

        offset = 0x1b
        OptionalHeader32["minorlinkerver"] = struct.unpack("<B", self.data[base+offset:base+offset+1])[0]

        offset = 0x1c
        OptionalHeader32["sizeofcode"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x20
        OptionalHeader32["sizeofinitializeddata"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x24
        OptionalHeader32["sizeofuninitializeddata"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x28
        OptionalHeader32["addressofentrypoint"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x2c
        OptionalHeader32["baseofcode"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x30
        OptionalHeader32["baseofdata"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x34
        OptionalHeader32["imagebase"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x38
        OptionalHeader32["sectionalignment"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x3c
        OptionalHeader32["filealignment"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x40
        OptionalHeader32["majoroperationsystemver"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x42
        OptionalHeader32["minoroperatingsystemver"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x44
        OptionalHeader32["majorimagever"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x46
        OptionalHeader32["minorimagever"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x48
        OptionalHeader32["majorsubsystemver"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x4a
        OptionalHeader32["minorsubsystemver"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x4c
        OptionalHeader32["win32ver"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x50
        OptionalHeader32["sizeofimage"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x54
        OptionalHeader32["sizeofheaders"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x58
        OptionalHeader32["checksum"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x5c
        OptionalHeader32["subsystem"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x5e
        OptionalHeader32["dllcharacteristics"] = struct.unpack("<H", self.data[base+offset:base+offset+2])[0]

        offset = 0x60
        OptionalHeader32["sizeofstackreverse"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x64
        OptionalHeader32["sizeofstackcommit"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x68
        OptionalHeader32["sizeofheapreverse"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x6c
        OptionalHeader32["sizeofheapcommit"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x70
        OptionalHeader32["loaderflags"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x74
        OptionalHeader32["numberofrvaandsizes"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        return OptionalHeader32




    def get_file_header(self):
        base = self.get_e_lfanew()
        offset = 0x4
        FileHeader = {}
        FileHeader["Machine"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]


        offset = 0x6
        FileHeader["NumberOfSection"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]

        offset = 0x8
        FileHeader["TimeDataStamp"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0xc
        FileHeader["PointerToSymbolTable"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x10
        FileHeader["NumberOfSymbols"] = struct.unpack("<L", self.data[base+offset:base+offset+4])[0]

        offset = 0x14
        FileHeader["SizeOfOptionalHeader"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]

        offset = 0x16
        FileHeader["Characteristics"] = struct.unpack("<h", self.data[base+offset:base+offset+2])[0]

        return FileHeader


    def get_e_lfanew(self):
        """ print file address of new exe header """
        e_lfanew = struct.unpack("<L", self.data[0x3c:0x40])[0]
        #print("0x{:08x}".format(self.e_lfanew[0]))
        return e_lfanew

    def read_data_from_file(self):
        """ open given file, close the file after reading all data from the file """
        fd = open(self.path, "rb")
        data = fd.read()
        fd.close()
        return data

    def print_MZ(self):
        """ boring thing """
        print("aha you find {0}{1} represent for"
              "Mark Zbikowski".format(chr(self.data[0]) ,chr(self.data[1])))

    def print_PE(self):
        """ print PE signature """
        print("{0}{1}".format(chr(self.data[self.e_lfanew]), chr(self.data[self.e_lfanew+1])))


    def get_dword(self, data):
        #将十六进制数据转换为小端格式的数值
        """ transfer hex value to litle-end value """
        return struct.unpack('<L', data)[0]

    def get_string(self, ptr):
        """ extract ASCII strings """
        beg = ptr
        while ptr < len(self.data) and self.data[ptr] != 0:
            ptr += 1
        return self.data[beg:ptr]

    def parse(self):
        self.read_data()
        if not self.is_valid_pe():
            print("[Error] Invalid PE file")
        self.parse_import_table()

#检查文件合法性并读取数据
    def is_valid_pe(self):
        pass

#RVA转偏移地址
    def rva_to_offset(self,rva):
        pass

#输入表结构解析
    def parse_import_table(self):
        pass

#解析每个IID对应的IMAGE_THUNK_DATA类型的INT数组
    def parse_iid_int(self,ptr):
        pass

if __name__ == "__main__":
    pe_file = PEParser("./FastStoneCapture9.3.0.exe")

    pe_file.analyse_import_by_name()

#   if len(sys.argv) == 2:
#       p = PEParser(sys.argv[1])
#	p.parse()




