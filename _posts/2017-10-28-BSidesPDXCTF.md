---
layout: post
title: "BSidesPDX CTF"
date: 2017-10-28
permalink: blog/BSidesPDXCTF/
---

## Links

[BSidesPDX CTF 2017 Source](https://github.com/BSidesPDX/CTF-2017)

[BSides PDX CTF 2017 Infrastructure](https://github.com/flamingspaz/bsides-infra)

[BSidesSF 2017 CTF](https://github.com/BSidesSF/ctf-2017-release)

[BSidesSF CTF Infrastructure pwnage](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)

## Introduction

Over the weekend of October 20th and 21st I ran the [BSidesPDX](https://twitter.com/bsidespdx) for the second year with an amazing team ([pwnpnw](https://twitter.com/pwnpnw), [yalam96](https://twitter.com/yalam96) and [andrewkrug](https://twitter.com/andrewkrug) with infrastructure supported by [Mozilla](https://twitter.com/mozilla)). We decided to run all of the challenges in Docker containers in Amazon Web Services (AWS), although at first we were using Google Cloud Platform (GCP), in a Kubernetes (k8s) cluster. This post will detail some of our decisions, where I see the CTF going (along with CTFs at other conferences, mainly targeting BSides) and go into what we can improve on. 

Firstly, you might be wonder what CTF is and what we targeted for this years. Copied and pasted from the description I came up with for the event "Capture the Flag (CTF) is a computer security competition where competitors hack on binaries, web services or challenges to uncover secret flags which earn you points. Join us at BSidesPDX and compete in a CTF that take competitors through a series of web & binary exploitation, shellcoding and reverse engineering challenges! Unlike CTFs at other conferences ours is not meant to be intimidating and there are some challenges that any attendee should be able to solve! Come and learn some new skills or freshen up on some of the basics, which are easily forgotten. This year will introduce new CTF infrastructure and we are excited about it!"

For the 2016 BSidesPDX CTF we ran all of our challenges in Docker Containers and already had the work flow as organizers on how to make that work. While brainstorming what to do for 2017, deciding to continue running challenges in Docker made the most sense. For 2016 we used a custom platform from Symantec to host all of the challenges and wanted to do something different. . . and we needed orchestration . . . so k8s was decided on. Having never with k8s before, I was excited to learn more. 

Around the time DEF CON rolled around, I was sitting at a Cabana at the Flamingo and ran into [CornflakeSavage](https://twitter.com/CornflakeSavage). I had previously seen what he and his team had done for the [BSidesSF CTF](https://github.com/BSidesSF/ctf-2017-release) and was inspired by the infrastructure decisions. He also authored a great blog article explaining some challenges of Docker and k8s for CTF which is viewable [here](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0). The TLDR of that blog article is that Docker did not necessarily work that well in the model as intended due to the fact we are giving competitors Remote Code Execution (RCE) vulnerabilities that are expected to grant them a shell in the container.  

Even though CornflakeSavage had discussed some downfalls to running a CTF this way, we still went for it as with prior knowledge of running last years, running it in Docker would be sufficient. 

## Challenges

For the 2017 CTF we had 16 challenges across 4 domains

- Web exploitation

- Binary exploitation

- Shellcoding

- Reverse Engineering

Pwnpnw and I wrote all 16 challenges and our concepts at a higher level are available [here](https://github.com/BSidesPDX/CTF-2017/blob/master/concepts.txt) and all of the source code for them is located at their respective category and level on the repo [here](https://github.com/BSidesPDX/CTF-2017). We each helped each other flush out the concepts and took charge of 8 challenges each. 

The challenges were meant to target beginner/intermediate players and I feel did a sufficient job of that. We had people in the event room that had never played a CTF before solving challenges and catting flags! 

## Infrastructure

When starting out with the CTF concept for this year, we knew we wanted to run everything in Docker containers and in k8s. Pwnpnw and I started off play testing cloud functionality in GCP (as is reflected in our open sourced repo, [here](https://github.com/BSidesPDX/CTF-2017/tree/master/deployTemplate)). We did this as at the time we had no external infrastructure support and were focusing on challenges and were planning to tackle some of the issues CornflakeSavage ran into. As seen from our reference [Makefile](https://github.com/BSidesPDX/CTF-2017/blob/master/deployTemplate/Makefile) we were going to use `gcloud` to host our docker images as well as the k8s [configurations](https://github.com/BSidesPDX/CTF-2017/tree/master/deployTemplate/deployment). This worked great and allowed us to both locally test in Docker-Compose (more on that later) and in a k8s cluster. 

However, I later reached out to AndrewKrug and he and yalam96 were ecstatic to help us out, along side Mozilla as our infrastructure hosting partner. This allowed Pwnpnw and I to focus on challenge creator and less on the perils of k8s security *shudders*. With the idea of full transparency, we also open sourced how we hosted the infra in AWS [here](https://github.com/flamingspaz/bsides-infra) and our reference of using it in the BSidesPDX CTF is [here](https://github.com/BSidesPDX/CTF-2017/tree/master/deployTemplate/aws). 

When we started brain storming what we wanted the k8s cluster to have we came up with this list

Lyft’s metadata proxy with appropriate DNAT redirects to prevent AWS Credential theft

Role Based Access Control ( Ideally against CoreOS Dex or Auth0 ) 

PodSecurityPolicy ( Admission Controller )

NodeRestriction Admission Controller

- Prevent Kubelets from modifying other nodes and pods bound to other nodes

NetworkPolicy Resources

- Use Canal or Calico Daemon set with Network Policy controller

Ensure that kublet / etcd have cert authentication only

Enable NodeAuthorizer to restrict kubelet access to resources belonging to pods.  Preventing pivots.

So, what did yalam96 do? *Note: this was discussed during the BSidesPDX 101 discussion on the 20th.*

Role-based Access Control (RBAC) to define roles and permissions for k8s API resources and objects. 

Calico network policy to deny all incoming traffic to all pods in the namespace. For example, in the [service.yaml](https://github.com/BSidesPDX/CTF-2017/blob/master/deployTemplate/aws/deployment/service.yaml) files that were deployed you can see the NetworkPolicy being defined to only allow traffic over a certain port. 

{% highlight yaml %}

kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: quickstart
spec:
  podSelector:
    matchLabels:
      app: quickstart
  ingress:
  - ports:
    - port: 80
    from: []

{% endhighlight %}

Fortunately we had a pretty easy NetworkPolicy as each container we deployed functioned on its own. We had no needed for inter-container communication. This made our deployment fairly trivial as all we had to do was change the port needed for each deployed pod. 

yalam96 also implemented

PodSecurityPolicy Admission Controller

- The pod security policy lets you control the characteristics of pods that are run in your cluster. The main use-case for this would be to by default deny pods running with host networking. It’s also possible to enforce docker best practices by denying pods to run as their root user, for example.

NodeRestriction Admission Controller

- By default in kubernetes any kubelet is allowed to see the resources for any pod in the cluster. The NodeRestriction admission controller ensures that kubelets can only access resources for the pods that have been scheduled to itself, creating a least-privilege model.

Use certificate auth for kubelets and etcd

- etcd knows all

- Manual installations might have no authentication for etcd, meaning an attacker can just read and manipulate the data in etcd directly rather than deal with the API

AWS metadata proxy

- Proxies all traffic to the metadata service and transparently assumes a role defined in the container environment.

As you can see, we worked hard to ensure that our k8s environment was secure! Of course, there were risks and Mozilla had a bug bounty available for the Infrastructure throughout the conference (and still running as the infra is still live at [BSidesPDXCTF.party](https://bsidespdxctf.party/).)

Thanks to yalam96, AndrewKrug and Mozilla (kudos to [0x7eff](https://twitter.com/0x7eff) as well) we had an awesome infrastructure to host all of the challenges Pwnpnw and I came up with!

## Scoreboard

Having used it in the past, going with [CTFd](https://twitter.com/ctfdio) was a no brainier. It is easy to deploy and administer. We hosted our scoreboard at [BSidesPDXCTF.party](https://bsidespdxctf.party/).

## Results

This year we had 

62 teams register

13 teams solved challenges 

Most solved: SeaQuell with 11 solves

Least solved: TinyThumb with 1 solves

Solved breakdown

- 11 SeaQuell

- 10 DoNotTrek

- 8 MakeIcon

- 4 Monolith

- 3 dotP33k

- 2 Cookie

- 2 lostIt

- 2 xordoz

- 1 TinyThumb

People liked solving the web challenges!

Final Scoreboard:

```
Place	Team				Score
1	b0tchsec			1600
2	Chicken_bit			1400
3	hack_the_planet			1000
4	ciph34block			900
5	lolbestname			800
6	Reenigneesrever			600
7	<svg/onload=alert(1)>		600
8	nopenop0x90			600
9	zero_cool			400
10	mdalin				300
11	Professor X			300
12	JoshGesler			300
13	therabbitreturns		200

```

## Open Source

Being influenced from the BSidesSF CTF and their openness about the challenges, infrastructure, etc I wanted to do the same for the community and CTF content creators. One of things I find frustrating about CTF challenge creation is that there is little to go off of for a base reference implementation. There are a plethora of write-ups for CTFs, but there is hardly ever any initial concepts for a challenge, how it was built or what it was meant to stress. Losing the source is one thing, but losing the concepts makes you fairly blind to how the event and challenges are ran. Furthermore, I wanted something reproducible for next year as I didn't want to fall into the same trap and needing to completely restart the baseline. 

I gave a talk this year reflecting some of these ideas,[https://speakerdeck.com/tophertimzen/the-trials-and-tribulations-of-building-your-own-ctf-and-shooting-gallery](The Trials and Tribulations of Building Your Own CTF and Shooting Gallery), and encouraged openness after the CTF event ends. 

Personally, I would love to see more base reference implementations of CTF building as it would make running the events a lot more seamless. I plan to use the same build pipeline next year and encourage other CTF creators to do the same. CornflakeSavage and team kicked off this movement, let's continue it!

As previously hinted at, our challenges, including source and solutions (minus RE) are available at [CTF-2017](https://github.com/BSidesPDX/CTF-2017). 

We also made it such that you can play the CTF locally. Due to the fact we wanted to give players binaries for some challenges, we decided to do all of the src building outside of the containers. They were all built on Ubuntu 16.04 with gcc version 6.3.0 20170406 (Ubuntu 6.3.0-12ubuntu2) 
and ldd (Ubuntu GLIBC 2.24-9ubuntu2.2) 2.24. Because of this, our solutions might not work on your platform in this method (which are in the /solutions/ directory of each challenge). 

## What To do Better

There are several things we could have done better for this event that we will work on improving for 2018!

For the challenges we used Xinetd, which is old and deprecated, and should move to systemd inside our containers. But hey, it's a CTF and it worked!

Start earlier in the year: We didn't get around to solving every challenge with a repeatable solution (in fact, pwn-400 was solved during the event to prove it was exploitable... it was, just not in the way we had intended). This was mainly due to only 2 of us working on challenge creation while also looking into our k8s implementation before Mozilla came on to help us. 

Continue to improve k8s cluster: One thing that happened during the event was pwn-200 would crash and never recover with Xinetd. I couldn't figure it out live and had t constantly redeploy it. 

More organizers: see below and watch my talk!

Live scoreboard: We did not even think of having a live pew pew scoreboard during the CTF in the event room.... our mistake. we will be better. 

## Get Involved!

If you want to help us run BSidesPDX CTF in anyway please reach out to me! We are eager to get some people stoked on writing challenges to make 2018 even better. The idea behind a base reference implementation is that the challenge creation comes to the foreground much easier and can be focused on without worrying about much else!


## Thanks 

I want to extend another huge thanks to 

- Everyone who played CTF at BSidesPDX

- The BSidesPDX organization team for being supportive of the CTF event

- [pwnpnw](https://twitter.com/pwnpnw) for challenge creation

- [yalam96](https://twitter.com/yalam96) and [andrewkrug](https://twitter.com/andrewkrug) with infrastructure support

- [Mozilla](https://twitter.com/mozilla) for hosting our challenges on their AWS instance and helping with the base k8s reference!