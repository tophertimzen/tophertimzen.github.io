---
layout: post
title: "Shellcode in .NET - How the PEB Changes"
date: 2015-04-17
permalink: blog/shellcodeDotNetPEB/
---

Shellcode commonly uses a method to resolve Windows API functions by traversing through the Portable Environment Block (PEB) to find Kernel32's base address. This is done so shellcode remains position independent while still having the ability to call LoadLibraryA and GetProcAddress to resolve other dlls and functions. The PEB has a_PEB_LDR_DATA structure that contains three linked lists of DLLs that are loaded in a processes memory space.  The three linked lists are 

InLoadOrder

- Order a module is loaded into process. *.exe is always first.

InMemoryOrder

- Order in which DLLs appear in memory. ASLR changes this.


InInitializationOrder

- Order of when the DllMain fires.

The following Volatility Volshell output shows the location of the _PEB_LDR_DATA in the PEB and the three lists for a 32 bit system

{% highlight python %}

>>> dt ("_PEB")
 '_PEB' (584 bytes)
0x0   : InheritedAddressSpace          ['unsigned char']
0x1   : ReadImageFileExecOptions       ['unsigned char']
0x2   : BeingDebugged                  ['unsigned char']
0x3   : BitField                       ['unsigned char']h
0x3   : ImageUsesLargePages            ['BitField', {'end_bit': 1, 'start_bit': 0, 'native_type': 'unsigned char'}]
0x3   : IsImageDynamicallyRelocated    ['BitField', {'end_bit': 4, 'start_bit': 3, 'native_type': 'unsigned char'}]
0x3   : IsLegacyProcess                ['BitField', {'end_bit': 3, 'start_bit': 2, 'native_type': 'unsigned char'}]
0x3   : IsProtectedProcess             ['BitField', {'end_bit': 2, 'start_bit': 1, 'native_type': 'unsigned char'}]
0x3   : SkipPatchingUser32Forwarders   ['BitField', {'end_bit': 5, 'start_bit': 4, 'native_type': 'unsigned char'}]
0x3   : SpareBits                      ['BitField', {'end_bit': 8, 'start_bit': 5, 'native_type': 'unsigned char'}]
0x4   : Mutant                         ['pointer', ['void']]
0x8   : ImageBaseAddress               ['pointer', ['void']]
0xc   : Ldr                            ['pointer', ['_PEB_LDR_DATA']]
[snip]

>>> dt("_PEB_LDR_DATA")
 '_PEB_LDR_DATA' (48 bytes)
0x0   : Length                         ['unsigned long']
0x4   : Initialized                    ['unsigned char']
0x8   : SsHandle                       ['pointer', ['void']]
0xc   : InLoadOrderModuleList          ['_LIST_ENTRY']
0x14  : InMemoryOrderModuleList        ['_LIST_ENTRY']
0x1c  : InInitializationOrderModuleList ['_LIST_ENTRY']
[snip]


{% endhighlight %}

The Ldr structure is at offset 0xc in the PEB and the InMemoryOrderModuleList is at offset 0x14 from the _PEB_LDR_DATA.

The InMemoryorderModuleList is the most widely used linked list, that I have seen, to resolve the base address of Kernel32. [Harmony Security](http://blog.harmonysecurity.com/2009_06_01_archive.html) has a write up of how to traverse the InMemoryorderModuleList on Windows 7 to allow shellcode to be more robust across Windows platforms. 

While the method Harmony Security mentions holds true for most applications and Windows environments, if shellcode is injected into a .NET process this method will not work. 

Shellcode payloads, especially ones from MetaSploit, rely on Kernel32.dll being the third entry in the InMemoryorderModuleList. However, in a .NET process, Kernel32.dll is the **4th** entry as Mscoree, the .NET bootstrapper for the default CLR host, is loaded before Kernel32. 

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

Fortunately, this is an easy adjustment in shellcode as the change is a one-liner!

In 32 bit code the traversal is as follows 

{% highlight asm %}

xor ebx, ebx               // clear ebx
mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
mov ebx, [ ebx ]           // get the next entry (2nd entry)
mov ebx, [ ebx ]           // get the next entry (3rd entry)
mov ebx, [ ebx + 0x10 ]    // get the 3rd entries base address (kernel32.dll)

{% endhighlight %}

To perform the same action in a .NET process, go to the 4th entry in the InMemoryOrderModuleList as seen below. 

{% highlight asm %}

mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink 
mov ebx, [ ebx ]           // get the next entry (2nd entry)
mov ebx, [ ebx ]           // get the next entry (3rd entry)
mov ebx, [ ebx ]           // get the next entry (4th entry)
mov ebx, [ ebx + 0x10 ]    // get the 4th entries base address (kernel32.dll)


{% endhighlight %}

This trick will also work with 64 bit .NET applications, although the offsets are different. 

{% highlight asm %}

mov rbx, [gs:60h]          // get a pointer to the PEB
mov rbx, [rbx + 0x18]      // get PEB->Ldr
mov rbx, [rbx + 0x20]      // get PEB->Ldr.InMemoryOrderModuleList.Flink
mov rbx, [rbx              // get the next entry (2nd entry)
mov rbx, [rbx]             // get the next entry (3rd entry)
mov rbx, [rbx]             // get the next entry (4th entry)
mov rbx, [rbx + 0x20]      // get the 4th entries base address (kernel32.dll)


{% endhighlight %}

While developing shellcode, be mindful of the platform and application you are injecting into. If you are going up against .NET, it is important to know where Kernel32 is in the Ldr lists so that its base address can be resolved. 