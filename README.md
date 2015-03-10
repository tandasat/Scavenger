Scavenger
========

It copies all files that were modified or being deleted to a C:\Windows\Scavenger\
directory.

It was developed primarily to familiarize myself with a mini-filter driver and
has no notable advantages to recommend others to use it.

Installation and Uninstallation
-----------------

Use a DrvLoader with a -F option.


Usage
-------

Once you have installed it, you should see output logs on DebugView and saved
files under the C:\Windows\Scavenger\ directory.


Caveats
-------
- It does not handle (1) a file whose size is zero or larger than 4GB, and (2)
any of operations done by a system thread.


Supported Platforms
-----------------
- Windows 7 SP1 x86


License
-----------------
This software is released under the MIT License, see LICENSE.


