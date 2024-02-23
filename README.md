FileTest
========

## Interactive File System Test Tool
You can use this tool for testing, debugging and learning [Windows FileSystem APIs](http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232(v=vs.85).aspx).
If you use this tool with [Process Monitor](http://technet.microsoft.com/en-us/sysinternals/bb896645.aspx), you can understand how Windows FileSystems internally works.

![Interactive File System Test Tool](http://www.zezula.net/images/tools/filetest_github.png)

## Supported ways to build
FileTest can be built with one of these build environments:
* Visual Studio 2022+
* Visual Studio 2008
* WDK 6001
* CMake

### How to build with Visual Studio 2008 or 2022+
```
md C:\Projects
cd C:\Projects
git clone https://github.com/ladislav-zezula/Aaa.git
git clone https://github.com/ladislav-zezula/FileTest.git
cd FileTest
call make-msvc.bat
```
The final EXEs will be in `./bin/Win32/Release` and `./bin/x64/Release`

### How to build with WDK 6001
1. Clone the repository `https://github.com/ladislav-zezula/WDK_6001`
2. Clone the repository `https://github.com/ladislav-zezula/FileTest`
3. Set the environment variable `WDKDIR` to the folder where you cloned the WDK
4. Run the build script
```
:: Assume C:\Projects as the current folder
git clone https://github.com/ladislav-zezula/WDK_6001.git
git clone https://github.com/ladislav-zezula/FileTest.git
git clone https://github.com/ladislav-zezula/Aaa.git
set WDKDIR=C:\Projects\WDK
cd FileTest
make.bat
```
The final EXEs will be in `.\objfre_w2k_x86\i386` and `.\objfre_wlh_amd64\amd64`

### How to build with CMake
```
git clone https://github.com/ladislav-zezula/FileTest.git
cd FileTest
git submodule add https://github.com/ladislav-zezula/Aaa.git ./lib/Aaa/
md build
cd build
cmake .. -G "Visual Studio 17 2022"                    :: For 64-bit build
cmake .. -G "Visual Studio 17 2022" -A Win32           :: For 32-bit build
cmake --build . --config Release
```
The final EXE fill be in `.\build\Release`