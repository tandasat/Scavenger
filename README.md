Scavenger
========

It copies all files that were modified or being deleted to a C:\Windows\Scavenger\
directory and is pretty much just a reference for the author. 

It was initially developed a long time ago to familiarize myself with a 
mini-filter driver apart from its original purpose and has no notable advantages 
to recommend others to use it any more as there are several open source projects 
do the same job (see [Cockoo Sandbox](http://cuckoo.readthedocs.org/en/latest/)
or [Capture-BAT](https://www.honeynet.org/node/315)).

Installation and Uninstallation
-----------------

Get an archive file for compiled files form this link:

    https://github.com/tandasat/Scavenger/releases/latest

Then use a [DrvLoader](https://github.com/tandasat/DrvLoader) with a -F option
on command prompt with the administrator privilege to install the driver.

On the x64 bit platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type 
the following command:

   >bcdedit /set {current} testsigning on
    
Then, reboot the system to activate the change.


Usage
-------

Once you have installed it, you should see output logs on DebugView and saved
files under the C:\Windows\Scavenger\ directory.


Caveats
-------
- It does not handle:
-- a file whose size is zero or larger than 4GB, or
-- any of operations done by a system thread.


Supported Platforms
-----------------
- Windows 7 SP1 and 8.1 (x86/x64)


License
-----------------
This software is released under the MIT License, see LICENSE.


