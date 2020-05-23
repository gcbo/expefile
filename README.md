# expefile
extend [pefile](https://github.com/erocarrera/pefile) module.
## feature
* add new section to pe 
* add new IID ,IAT,dll
* add new reloc
* inject binary code to pe 
* convert memory mapped data to  pe raw file when you handle dumped file
## how to use

1. add a new section
2. add dll , IAT
3. add imps to new section
4. add code to new section
5. write to new file
## example
```python
import struct
import expefile

filename = 'helloworld.exe'
binary  = expefile.PE(filename)
# code you want to inject to
code = b'\x6a\x00' \
       b'\x68\x34\x81\x40\x00'\
       b'\x68\x34\x81\x40\x00'\
       b'\x6a\x00'\
       b'\xff\x15\xe8\x80\x40\x00'\
       b'\xe9\x00\x00\x00\x00'
code = bytearray(code)
# push 0x0
# push title
# push text
# push 0x0
# call dword ptr ds:[<&MessageBoxA>]
# jmp entrypoint
title = b'MsgBox' + b'\x00'
text = b'hacked by gcbo!' +b'\x00'
entry  = binary.OPTIONAL_HEADER.AddressOfEntryPoint + binary.OPTIONAL_HEADER.ImageBase
msgbox = binary.get_imp_from_name(b'MessageBoxA')

new_sec_rva = binary.get_new_section_rva()
if not msgbox:
    if binary.add_section(b'gcbo', new_sec_rva, 0x1000):
        binary.add_imp_fun(b'user32.dll',b'MessageBoxA')
        imps_data_len = binary.add_imps_to_sec(b'gcbo',new_sec_rva)
        msgbox = binary.get_imp_from_name(b'MessageBoxA')
else:
    if binary.add_section(b'gcbo', new_sec_rva, 0x1000):
        print('add succ')
# the code rva you want to write
title_rva = new_sec_rva+ imps_data_len

text_rva  = title_rva + len(title)
code_rva = text_rva + len(text)
def copy_to(src,index,dst):
    for d in dst:
        src[index] = d
        index += 1

# write va addr to code to build executable binary code
copy_to(code,3,struct.pack("<i",title_rva+ binary.OPTIONAL_HEADER.ImageBase))
copy_to(code,8,struct.pack("<i",text_rva+ binary.OPTIONAL_HEADER.ImageBase))
copy_to(code,(len(code)-9),struct.pack("<i",msgbox.address))

# hook entry or other addr you want to hook
jmp_entry = binary.OPTIONAL_HEADER.AddressOfEntryPoint- code_rva - len(code)
copy_to(code,(len(code)-4),struct.pack("<i",jmp_entry))
data = title + text + code
binary.copy_to_rva(title_rva,data)
binary.OPTIONAL_HEADER.AddressOfEntryPoint  = code_rva

# add reloc entry for va addr
if binary.has_relocs():
    binary.add_reloc(title_rva)
    binary.add_reloc(text_rva)
    binary.add_reloc(code_rva)
    binary.add_relocs_to_sec()

# reset checksum
binary.reset_checksum()
# write to new file
binary.write('add_MsgBox_'+filename)

```