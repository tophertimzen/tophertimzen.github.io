---
layout: page
title: Lab2
permalink: /cs407/labs/lab2.html
---

#Using the Toolset

Assigned: April 8th

Due: April 17th by 11:59 PM PST 

Requirements

- Use several Volatility plugins to hypothesize the state of a Windows system.

- Look at a Windows XP image and analyze DKOM 

Complete the following by writing a thorough report on the actions you took and the assumptions you made. Preferably, give each command used and its flags. 

Think like an investigator writing a report!

##Part 1

---

Using the memory imaged you captured during Lab1, run several Volatility plugins on it and discuss what you discovered. 

For each command ran give it meaning by describing what it does and explain what the results mean for your memory image. 

Run the following using the above criteria:

1. pooltracker

2. filescan

3. pslist

4. psxview

5. psscan

6. dllist (pick a process from the process scans)

Answer the following:

1. What are the differences between pslist, psxview and psscan?

2. What is the advantage of using a combination of process scanner plugins?

##Part 2

---

Download the memory image from [https://www.dropbox.com/s/fsycx69csdpt18e/Lab2.vmem](https://www.dropbox.com/s/fsycx69csdpt18e/Lab2.vmem)

*note: This memory image is from a VMWare snapshop of Windows XP and Volatility can analyze .vmem images*

1. A process or two have been unlinked from the PsActiveProcessList, which ones? 

2. Do the process/processes unlinked have any importance? *Might require Google* 

	- Why would an attacker want to use such a tool?

3. Describe in-depth how DKOM works. What is needed and how do you get it there? 

	- Bonus: What there security mitigations, if any, are in Windows 7 to make this harder?

4. Are there any children processes of one of the unlinked processes? 

5. When did the child from question 4 exit? Did it run long?

6. For the process you found in question 4

- Enter into volshell

- use the physical offset given from a process plugin to list the _EPROCESS structure

	- What was the Pcb address, Unique Process Id and Exit Status?

BONUS Valuable Valueless Prize Tokens: Using the modules() command in volshell, can you spot the malicious driver that was used?

---



Turn in by e-mail to <a href="mailto:timzenc@sou.edu?Subject=memForensicsLab1" target="_top">timzenc@sou.edu</a>.
