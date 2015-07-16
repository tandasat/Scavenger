Scavenger
==========

It copies all files that were modified or being deleted to a
C:\Windows\Scavenger\ directory.

It was initially developed to familiarize myself with a mini-filter driver and
unlikely to have any notable advantages over using other open source projects 
such as [Cockoo Sandbox](http://cuckoo.readthedocs.org/en/latest/)
or [Capture-BAT](https://www.honeynet.org/node/315).


Installation and Uninstallation
--------------------------------

Get an archive file for compiled files form this link:

    https://github.com/tandasat/Scavenger/releases/latest

1. Extract the zip file and deploy appropriate version of files onto a target 
   system.
2. On the target system, execute install.bat with the administrator privilege.

On the x64 bit platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type 
the following command, and then reboot the system to activate the change.

   >bcdedit /set {current} testsigning on

To uninstall the program, execute uninstall.bat with the administrator privilege.

Alternatively, you can use a [DrvLoader](https://github.com/tandasat/DrvLoader)
with a -F option on command prompt with the administrator privilege.


Usage
------

Once you have installed it, you should see output logs on DebugView and saved
files under the C:\Windows\Scavenger\ directory.


Caveats
-------
- It does not handle:
-- a file whose size is zero or larger than 4GB, or
-- any of operations done by a system thread.


Supported Platforms
--------------------
- Windows 7 SP1 and 8.1 (x86/x64)


License
--------
This software is released under the MIT License, see LICENSE.
