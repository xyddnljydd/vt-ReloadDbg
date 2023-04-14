# vt-ReloadDbg

## 实现

下面的结构需要自己去稍微修改一下

#define  Thread_CrossThreadFlags 0x448

#define  Thread_RundownProtect 0x430

#define  Process_DebugPort 0x1f0

#define  Process_RundownProtect 0x178

#define  ProcessFlagS 0x440

#define  ProcessSectionObject 0x268

#define  ProcessSectionBaseAddress 0x270

#define  ThreadStartAddress 0x388

主要实现了win7（sp1）和win10（20h1），里面这些进程结构的偏移是写死的，需要你根据当前的Windows版本修改，其他地方到没什么需要修改的。

## 说明

采用的是下载符号，传到内核，这样没必要动态定位dbg的部分函数，需要先加载驱动，在执行LoadSymbol.exe，执行的时候需要dbghelp.dll和symsrv.dll的依赖。

没有完全重写调试体系，主要涉及debugport的地方都重写了。

## vt部分

由于各种vt检测的缘故，这里替换vt为jono大佬写的，处理的已经很完善了。win7不支持性能控制器，会出现BSOD，这里把win7下的IA32_PERF_GLOBAL_CTRL给注释掉。Hook函数原作者没写，但提供了ept的替换页表，简单的实现了hook函数，但不支持跨页。

## 参考

1.https://bbs.kanxue.com/thread-260034-1.htm

2.https://github.com/Air14/HyperHide

3.https://github.com/DragonQuestHero/Kernel-Anit-Anit-Debug-Plugins

4.https://github.com/jonomango/hv
