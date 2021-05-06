FileTest
========

### Interactive File System Test Tool
You can use this tool for testing, debugging and learning [Windows FileSystem APIs](http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232(v=vs.85).aspx).
If you use this tool with [Process Monitor](http://technet.microsoft.com/en-us/sysinternals/bb896645.aspx), you can understand how Windows FileSystems internally works.

![Interactive File System Test Tool](https://dl.dropboxusercontent.com/u/29668275/filetest.png)

### Build Requirements
To build FileTest, you need to have one of these build environments
* Visual Studio 2017
* Visual Studio 2008
* WDK 6001

1) Make a new directory, e.g. C:\Projects
```
   md C:\Projects
   cd C:\Projects
```
2) Clone both [Aaa](https://github.com/ladislav-zezula/Aaa) and [FileTest](https://github.com/ladislav-zezula/FileTest)
```
   git clone https://github.com/ladislav-zezula/Aaa.git
   git clone https://github.com/ladislav-zezula/FileTest.git
```
3) Go to C:\Projects\FileTest
```
   cd C:\Projects\FileTest
```
4) Build FileTest using your favorite build environment. Supported are Visual Studio 2017 (use `FileTest_vs17.bat`), Visual Studio 2008 (use `FileTest_vs08.bat`) or Windows Driver Kit (use `make.bat`).
```
   FileTest_vs17.bat
```
