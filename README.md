BinaryNinja Annotator (version 0.1)
====================
This is a plugin for Binary Ninja Reversing Platform.
Upon encountering a libc function call this plugins uses virtual stack to
annotate previous instructions with appropriate comment stating argument prototype.

> **Note**
> To send bug reports, feature requests, or whisky, simply drop a mail to michal.melewski@gmail.com

_Plugin is under development and only linux_x86 stack is implemented for now.
New stacks will be added later. Bug reports are welcome._

## Repository structure
### headers/
This directory contains some python scripts and flat text files with function prototypes.
I use it for generating *all_functions.json* that contain all known prototypes.
As a source I use [Zach Riggle functions library](https://github.com/zachriggle/functions).
In case you want to generate your own set you can do it like this:
```
./headers/parser.py <directory/> <file.prot> ... > functions.json
```
Parser accepts both directories and files as a source. Expected format is one
function prototype per line.

## samples/
This directory contains some simple programs written in C. I use them to test if my plugin works
after some changes. For now there are only compiled to 32bit executable, but 64bit support will be added in the future,
as well as more complicated examples.

## src/
This directory contains plugin itself. Inside you will find *data/* folder with function prototypes,
*modules/* with core plugin functionality and *modules/stacks/* with various VirtualStack implementations.
