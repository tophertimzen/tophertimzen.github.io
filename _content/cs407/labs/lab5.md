---
layout: page
title: Lab5
permalink: /cs407/labs/lab5.html
---

#Final Lab of Doom

Assigned: May 20th

Due: June 8th by 5:19 PM (Date and end of final) 

This is it... 

Requirements

- Reverse Engineer Malware with IDA and Volatility 

Good luck. 

---

The memory sample can be obtained [here](https://www.dropbox.com/s/ed8p7v0zv1r6v8w/lab5.vmem?dl=0)

Lab will be graded on the following criteria 

- What did the malware do?
- How did malware stay persistent?
- How did the malware resolve API functions?
	- Where any API functions used without obfuscation? If so, which ones? 
- How did the malware ensure only one version of itself was running? 
- How did the malware exfiltrate data?
	- Did any data get exfiltrated while this machine was running? 
		- How can you tell? 
- How did the malware hide from the user? 

Hints

- Use the memory forensics six step approach 
- Use hashing.py from lab 3
	- Know which DLLs were used (more than one this time) 
- Use the [Command Reference ](https://code.google.com/p/volatility/wiki/CommandReference)
- Fix ImageBase before running dumped file through IDA with below script 
- I did not strip the pdb... you're welcome
- Some line by line assembly will be needed, but most of the logic is higher level. This malware was written in C++ so there is a lot of metadata. 

{% highlight python %}

#!/usr/bin/env python
import pefile
pe = pefile.PE("malware.exe", fast_load = True)
pe.OPTIONAL_HEADER.ImageBase = BASEADDRESSHERE
pe.write("malware.exe")

{% endhighlight %}

---

Turn in by e-mail to <a href="mailto:timzenc@sou.edu?Subject=cs407_lab5" target="_top">timzenc@sou.edu</a>.

Enjoy the summer. 



