# v2.1 基于共享内存的进程通信机制实现（类似于管道）

## 单个实例
每个命名的共享内存只能被一对Client和Server使用. 如果使用`CreateSharedMemory`多次创建同名共享内存，则会返回错误.

## bi-directional (全双工)
Both client and server processes can read from and write to the shared memory.

## 阻塞模式
- **Server申请共享内存成功后，需要阻塞地等待Client的连接，该功能在用户层的接口是`ConnectSharedMemory`. 阻塞的实现：循环检测连接状态，直到连接建立。**
- **实现`ReadSharedMemory`的阻塞：Client（或Server）调用`ReadSharedMemory`时，需要等待直到Server（或Client）完成写入.**
- **`WriteSharedMemory`将数据写入共享内存后，取消`ReadSharedMemory`的阻塞.**
- **要实现上述阻塞功能，需要在`MEMORY_TABLE`结构体中记录Client的连接状态、Client和Server的阻塞状态；实现相关功能的函数是`WaitForConnection`,`Block`和`Unblock`.**
- **任意一方断开连接后，对方的`ReadSharedMemory`或`WriteSharedMemory`返回错误.**
- **对一些标记变量的访问加锁，涉及`Block`、`Unblock`以及检测连接状态的几个函数.**

****

## 关于地址空间的疑惑？
### 问题：
当Server陷入内核后，向共享内存里写数据，然后Client陷入内核，读取Server写入共享内存的数据，这个过程可以正确进行，因为内核模块维护了共享内存的元数据信息，里面记录了共享内存的虚拟地址。不论Server还是Client，在陷入内核后都可以正确地读取元数据中记录的共享内存的虚拟地址，从而读写这块共享内存，但是两个用户程序的地址空间不同（CR3的内容不同），他们陷入内核后，内核模块里的访存实则是在不同的地址空间里进行的，而共享内存最初是在Server的地址空间里完成分配的，即，共享内存的虚拟地址应该只在Server的地址空间有效，为什么Client陷入内核后可以直接通过该虚拟地址访问共享内存？
### 解答：
每个进程的地址空间是相互隔离的，进程的地址空间分为两部分。一部分供进程独立使用，称为用户空间；另一部分容纳OS的内核，称为内核空间。具体到可以容纳 4GB 内存空间的32位Windows操作系统，低 2GB 是用户空间，高 2GB 是内核空间。每个进程的用户空间是独立的，但内核空间是共享的。

共享内存的分配是在内核空间进行的，通过调试可以验证，在内核模块中的任何变量的地址，以及内存分配函数返回的地址，都大于`0x8000-0000`—— 2GB。共享内存位于内核空间，在Server和Client的地址空间内都可以访问，但必须要陷入内核。