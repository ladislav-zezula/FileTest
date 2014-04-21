
Utility: 	FileTest V1.1
Author:		Ladislav Zezula
Email:		ladik@zezula.net

This ZIP archive includes the sources (and executable) for the FileTest
utility, written by Ladislav Zezula.

The archive also includes the source of a general purpose "Utils" lib
which contains some generally useful functions and is also necessary
to build the executable.

The project and library are made for MS Visual C 6.0 and Visual Studio 7.0.
All necessary headers should be included (you will not need to include
NT DDK or IFS headers).


From the author:
================
If anyone has some criticisms, comments, suggestions, bugs, or anything else,
please mail me, I will try to help.

You may use the tool and the source code freely, whatever you need it for,
regardles if it is for personal or commercial use. The program is nothing
special, everyone could write it, if (s)he has time for it.

Building FileTest
=================

 1) Unpack the whole archive as-is to an empty directory
 2) Open the workspace "Utils\Utils.dsw
 3) In MSVC 6.0, select "Build\Batch Build" and rebuild all versions
 4) Open the workspace "FileTest\FileTest.dsw"
 5) Choose debug or release version and do "Rebuild all"
 6) The result executable is in "Debug\FileTest.exe" or
    "Release\FileTest.exe"


Warranty and Limitation of Liability:
=====================================
This program is provided as a service to the Windows system software development community
via OSR Online (www.osronline.com).  OSR Open Systems Resources, Inc not contributed to,
reviewed, or approved this program or any of the contents of this ZIP archive (except this file).

OSR Open Systems Resources, Inc. (OSR) expressly disclaims any warranty. THIS SOFTWARE IS PROVIDED
"AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION, THE
IMPLIED WARRANTIES OF MECHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK ARISING
FROM THE USE OF THIS SOFTWARE REMAINS WITH YOU. OSR's entire liability and your exclusive remedy shall not
exceed the price paid for this material.  In no event shall OSR or its suppliers be liable for
any damages whatsoever (including, without limitation, damages for loss of business profit,
business interruption, loss of business information, or any other pecuniary loss) arising
out of the use or inability to use this software, even if OSR has been advised of the possibility
of such damages.  Because some states/jurisdictions do not allow the exclusion or limitation
of liability for consequential or incidental damages, the above limitation may not apply to you.
