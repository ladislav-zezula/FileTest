FileTest
========

### Interactive File System Test Tool
You can use this tool for testing, debugging and learning [Windows FileSystem APIs](http://msdn.microsoft.com/en-us/library/windows/desktop/aa364232(v=vs.85).aspx).
If you use this tool with [Process Monitor](http://technet.microsoft.com/en-us/sysinternals/bb896645.aspx), you can understand how Windows FileSystems internally works.

![Interactive File System Test Tool](http://www.zezula.net/images/tools/filetest_001.png)

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
2) Run the following batch script
```
git clone https://github.com/ladislav-zezula/Aaa.git
git clone https://github.com/ladislav-zezula/FileTest.git
cd FileTest
call make-msvc.bat
```
