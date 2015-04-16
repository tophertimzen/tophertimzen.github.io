---
layout: page
title: lab3
permalink: /cs407/labs/lab3.html
---

#Understanding Malware

Assigned: April 22nd

Due: May 4th by 11:59 PM PST 

Requirements

- Use IDA to reverse engineer a piece of shellcode 

Complete the following by writing a thorough report on the actions you took and the assumptions you made. 

---

You are a Malware Investigator at 0xC0ff33, Inc and an incident responder came across injected shellcode during an investigation. He has done all he can in IDA and has passed on the .idb file to you. Figure out what the purpose of the malware was and how it achieved its goals. 

The IDA Database file and Python script for ROR13 are located here. [lab3Resources.zip](/resources/cs407/labResources/lab3Resources.zip)

Lab will be graded on the following criteria 

- Discovered what API functions were used
- Discovered how the API functions were resolved and what hash cipher was used
- What the malware created on the system 
- How the malware traversed the PEB 
- How the malware traversed the PE 

I am looking for an analysis of the shellcode and the way that it parsed the PE and PEB structures we discussed to achieve its goal. 

*Hint: I only used functions from kernel32.dll*

---

Turn in by e-mail to <a href="mailto:timzenc@sou.edu?Subject=cs407_lab3" target="_top">timzenc@sou.edu</a>.
