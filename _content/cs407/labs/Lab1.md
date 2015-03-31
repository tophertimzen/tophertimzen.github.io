---
layout: page
title: Lab1
permalink: /cs407/labs/lab1.html
---

#Learning the Toolset

Assigned: April 1st

Due: April 8th 

Requirements: Use the tools discussed to look at the footprint of winpmem while acquiring memory and using Volatility's ImageInfo. 

You are a forensics investigator at 0xC0ff33, Inc and have been alerted that an employee browsed to a malicious website on a Windows workstation. You have been tasked to look at the memory of that users system.  

Complete the following by writing a through report on the actions you took and the assumptions you made. Preferably give each command used and its flags. 

Think like an investigator writing a report! 

1. Use winpmem to acquire memory on your system.

2. While acquiring memory, use several tools to analyze the footprint winpmem leaves behind. Use the ones we discussed in class... regshot, procexp, procmon...

3. Looking at the winpmem footprint, what are some ways an attacker could utilize that information to prevent memory acquisition or hide themselves from an acquisition tool? 

4. Run the [imageinfo](https://code.google.com/p/volatility/wiki/CommandReference#imageinfo "imageinfo") Volaility plug-in on the memory dump. Does the profile match what version of Windows you ran winpmem on? Show the output of the plug-in. 

BONUS Valuable Valueless Prize Tokens: Find other tools that assist in discovering the footprint a process leaves on a system and use them in step 2. 

Turn in by e-mail to <a href="mailto:timzenc@sou.edu?Subject=memForensicsLab1" target="_top">timzenc@sou.edu</a>.
