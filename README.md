# lldb_script
some lldb python scripts


If there is no special explanation, they all use the environment of python3.7, i use them on lldb ver10.0.

一些 lldb 的脚本，如果没有特别的说明，都是基于 python3.7 的环境，我使用的是 lldb10.0；

# now there are:
- ## lldb "breakpoint write" fix
  aim to fix lldb's "breakpoint write" command.
  
  修复 lldb "breakpoint write" 命令。
  
- ## lldb-capstone-arm-ex
  enhanced [lldb-capstone-arm](https://github.com/upbit/lldb-capstone-arm), disassemble code by Capstone Engine, aim to replace lldb's default disasm feature on the situation that no debug symbol, tested in ARM(Thumb).
  
  增强版的 [lldb-capstone-arm](https://github.com/upbit/lldb-capstone-arm)，使用 Capstone Engine 的反汇编插件，旨在替代没有调试符号的情况下的反汇编功能，相对于原版插件，增加了其他平台的支持，但仅在 ARM(Thumb) 中测试较多。
