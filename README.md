# vt-ReloadDbg

实现

这里需要自己去稍微修改一下

#define  Thread_CrossThreadFlags 0x448

#define  Thread_RundownProtect 0x430

#define  Process_DebugPort 0x1f0

#define  Process_RundownProtect 0x178

#define  ProcessFlagS 0x440

#define  ProcessSectionObject 0x268

#define  ProcessSectionBaseAddress 0x270

#define  ThreadStartAddress 0x388


主要实现了win7（sp1）和win10（20h1），里面有些进程结构的偏移是写死的，需要你根据当前的EPROCESS和ETRHEAD稍微修改一下。
采用的是下载符号，传到内核，这样没必要动态定位dbg的部分函数.

没有完全重写调试体系，主要涉及debugport的地方都重写了

vt部分

hook函数有airhv版本，建议编译mini版本，非mini版本中部分反调试出现r3查询idt而引发的irql错误

同时也内嵌了一个vt，用的是ShotHv，这里对里面的ept和cr3做了部分修改

参考

1.https://bbs.kanxue.com/thread-260034-1.htm

2.https://github.com/Air14/HyperHide

3.https://github.com/DragonQuestHero/Kernel-Anit-Anit-Debug-Plugins

4.https://github.com/qq1045551070/ShotHv
