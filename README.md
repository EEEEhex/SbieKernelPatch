# SbieKernelPatch
通过BYOVD方法试用Sandboxie-Plus的高级功能, 请仅用于测试使用.

## 原理
[基于BYOVD方法无限使用SandboxiePlus的高级功能](https://bbs.kanxue.com/thread-287189.htm)  
[试用Sandboxie-Plus高级功能的另一种思路](https://bbs.kanxue.com/thread-288315.htm)  

## 使用方法
1. 关闭系统的驱动加载保护 (Microsoft易受攻击的驱动程序阻止列表)  
2. 在命令行中使用(以管理员身份运行):  
```
.\SbieKernelPatch.exe -n
```
这将生成新的密钥对(skp_public_key.blob/skp_private_key.blob), 然后生成证书文件, 并进行Patch. 其中-n的作用是生成新密钥对, 可以不使用-n, 将会使用内置的密钥对.  
SbieKernelPatch在启动时候会判断当前目录是否存在skp_public_key.blob/skp_private_key.blob, 若存在则使用blob文件中的密钥数据.   

## 其他命令
使用-h查看帮助.  
```
.\SbieKernelPatch.exe -c Certificate.dat
```
这将使用生成的密钥对(或内置密钥对)对Certificate.dat重新签名

