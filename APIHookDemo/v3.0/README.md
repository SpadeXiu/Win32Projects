# HookFileOperation

**该工具不仅限于Hook文件操作相关的API，还支持任意API的Hook操作.**

****

用`MyXXX`替换被监视进程的`XXX`调用，`NyXXX`先将文件操作信息记入日志，再调用`XXX`，保证被监视进程的`XXX`调用正常进行.

## 实现过程
`Hooker.exe`将`Hook.DLL`注入进程A，`Hook.DLL`被加载后修改进程A的`IAT`从而实现API Hook，并用`tool.dll`导出的函数`MyXXX`替换进程A的`XXX`调用.

## 结果
进程A的相关API调用信息被记入日志

## 目前支持Hook的API:
- `CreateFileW`/`CreateFileA`
- `ReadFile`
- `ShellExecuteW`/`ShellExecuteA`

## 细节说明
不仅进程A的主模块(即exe执行文件映像)中相关API会被拦截，而且除了用来装载替代函数的`Tool.DLL`以外的所有模块都将被处理到.