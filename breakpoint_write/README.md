# lldb "breakpoint write" fix

The lldb's "breakpoint write" command has some bugs:

1. standard "breakpoint write" will never write "ModuleName" field, even if it's a "Address type Breakpoint" 
    
    ->  **i added it**;
2. when there is a library with symbols, then "AddressOffset" field is the offset from section, and "Offset" is 0, i think "Offset" maybe corresponding section offset from file;  
    
    ->  **i calculate and filled the "AddressOffset" field with the offset from file**;


![Alt text](https://github.com/wizdzz/lldb_script/blob/master/breakpoint_write/2.png)
![Alt text](https://github.com/wizdzz/lldb_script/blob/master/breakpoint_write/1.png)
