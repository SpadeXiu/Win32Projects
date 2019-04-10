# 基于共享内存的进程通信机制
## v2.0
- `IoDevicePlus`使用`LIST_ENTRY`管理多个进程申请的共享内存，支持多对C/S架构的用户程序的通信
- 模仿Windows的命名管道，使用字符串命名一段共享内存，并设计了类似于“句柄”的东西来标识共享内存，用户程序提供共享内存的名字，内核将该共享内存的“句柄”返回给用户程序。“句柄”实质是内核空间位于链表中的`MEMORY_TABLE`项的虚拟地址.

详情参见[docs](./docs/)

## update
- 对共享内存的操作接口封装为静态库. 工程见`SharedMemoryLib`
- 用于测试的应用程序静态链接到库`SharedMemoryLib.Lib`. 工程见`user_app(using_lib)`
