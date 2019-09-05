# lldb-capstone-arm-ex

Based on [lldb-capstone-arm](https://github.com/upbit/lldb-capstone-arm)

A lldb script for disassemble ARM(Thumb)/ARM64 code by [Capstone Engine](https://github.com/aquynh/capstone)

## Setup
Install [capstone](https://github.com/aquynh/capstone) and Python bindings:
```
brew install capstone
sudo pip install capstone
```

Then deploy scripts:

1. Unzip and move *.py to ~/.lldb
2. Load script in lldb like: command script import ~/.lldb/dis_capstone.py

or add command script import ~/.lldb/dis_capstone.py to ~/.lldbinit (create if not exists)

## What hava I added or enhanced
1. Remove disasm bytes on normal mode, only show them on full mode.
2. Auto change mode between **CS_MODE_THUMB** and **CS_MODE_ARM**, the mode is determined by the cpsr flag on the original script, when it's different with disassembly position, the original may not work.
3. Change **disassemble bytes count** to **disassemble line count**.
4. Add symbols of addresses on disasm line, if can not find any symbol, then show the offset to the corresponding library.
