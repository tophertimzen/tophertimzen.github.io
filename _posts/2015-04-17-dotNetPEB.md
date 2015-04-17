---
layout: post
title: "Shellcode in .NET - How the PEB Changes"
date: 2015-04-17
categories: shellcode
---

Shellcode commonly uses a method to resolve Windows API functions by traversing through the Portable Environment Blocks (PEB) _PEB_LDR_DATA structure which contains three linked lists of DLLs that are loaded in a process space.  

_PEB._LDR_DATA contains 3 circular linked lists of loaded modules

InLoadOrder

- Order module is loaded into process. *.exe is always first.

InMemoryOrder

- Order in which DLLs appear in memory. ASLR changes this.


InInitializationOrder

- When the DllMain fires.

The InMemoryorderModuleList is the most widely used, that I have seen, method to resolve Kernel32 functions. [Harmony Security](http://blog.harmonysecurity.com/2009_06_01_archive.html) has a write up of how to traverse the InMemoryorderModuleList on Windows 7 to allow shellcode to be more robust across Windows platforms. 

While this method holds true for most applications, if shellcode is injected into a .NET process this method will not work. 

Shellcode, especially ones from MetaSploit, rely on Kernel32.dll being the third entry in the InMemoryorderModuleList as it typically is. However, in a .NET process, Kernel32.dll is the **4th** entry as Mscoree, the .NET bootstrapper for the default CLR host, is loaded before Kernel32. 

{% highlight bash %}

0:005> !peb
PEB at 7efde000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes
    ImageBaseAddress:         012b0000
    Ldr                       77b40200
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 00273a80 . 00301d48
    Ldr.InLoadOrderModuleList:           002739e0 . 00301d38
    Ldr.InMemoryOrderModuleList:         002739e8 . 00301d40
            Base TimeStamp                     Module
         12b0000 54f4a118 Mar 02 09:42:48 2015 C:\Users\Blob\DllInjector.exe
        77a40000 521ea8e7 Aug 28 18:50:31 2013 C:\Windows\SysWOW64\ntdll.dll
        73a10000 4b90752b Mar 04 19:06:19 2010 C:\Windows\SYSTEM32\MSCOREE.DLL
        75fc0000 53159a85 Mar 04 01:19:01 2014 C:\Windows\syswow64\KERNEL32.dll


{% endhighlight %}



Because of this, shellcode written for .NET applications needs to walk the _LIST_ENTRY structure for the Ldr lists to the 4th entry instead of the 3rd.

Fortunately, this is easy to adjust in shellcode as the change is a one liner!

In 32 bit code this change is

{% highlight asm %}

xor ebx, ebx               // clear ebx
mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
mov ebx, [ ebx ]           // get the next entry (2nd entry)
mov ebx, [ ebx ]           // get the next entry (3rd entry)
mov ebx, [ ebx + 0x10 ]    // get the 3rd entries base address (kernel32.dll)

{% endhighlight %}

TO

{% highlight asm %}

mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink 
mov ebx, [ ebx ]           // get the next entry (2nd entry)
mov ebx, [ ebx ]           // get the next entry (3rd entry)
mov ebx, [ ebx ]           // get the next entry (4th entry)
mov ebx, [ ebx + 0x10 ]    // get the 4th entries base address (kernel32.dll)


{% endhighlight %}

This trick will also work with 64 bit .NET applications, although the addresses are much different. 

{% highlight asm %}

mov ebx, [gs:60h]       // get a pointer to the PEB
mov ebx, [ebx + 0x18]	// get PEB->Ldr
mov ebx, [ebx + 0x20]	// get PEB->Ldr.InMemoryOrderModuleList.Flink
mov ebx, [ebx]			// get the next entry (2nd entry)
mov ebx, [ebx]			// get the next entry (3rd entry)
mov ebx, [ebx]			// get the next entry (4th entry)
mov ebx, [ebx + 0x20]	// get the 4th entries base address (kernel32.dll)


{% endhighlight %}

While developing shellcode, be mindful of the platform and application you are injecting into. If you are going up against .NET, it is important to know where Kernel32 is in the Ldr lists so that its base address can be resolved so the payload can acquire offsets to LoadLibraryA and GetProcAddress. 