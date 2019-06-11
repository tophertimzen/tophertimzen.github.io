---
layout: post
title: "BSidesPDX CTF Framework"
date: 2019-06-10
permalink: blog/BSidesPDXCTFFramework/
---

# Introduction

At [BSidesPDX](https://twitter.com/bsidespdx) I get up on stage during the 101 track and talk about the CTF, or at least I have in the last few years. I constantly have a call to action for people to write CTF challenges for us and get a lot of interested individuals. Having ran the [BSidesPDX](https://twitter.com/bsidespdx) CTF in 2016, [2017](https://www.tophertimzen.com/blog/BSidesPDXCTF2017/), [2018](https://www.tophertimzen.com/blog/BSidesPDXCTF2018/) and running the [OMSI MakerFaire CTF](https://github.com/BSidesPDX/OMSI-CTF-2018), I have made it a point to talk about the open source framework I created to help run it. I talk about the Open Source implementation in the [2017](https://www.tophertimzen.com/blog/BSidesPDXCTF2017) blog post and have spoken about it at events such as [HackBoat](https://speakerdeck.com/tophertimzen/a-history-of-the-bsidespdx-ctf) but have never blogged about it. I find myself repeating to each how we run and write challenges without having a source of knowledge, other than the open source repos, to get started. This blog post will help solve these issues.

The [bsides-ctf-framework](https://github.com/tophertimzen/bsides-ctf-framework) repo was setup in hopes to make it easier to determine what we are doing in a scaled down manner, as well as providing an example folder. 

# Framework

Pulled from my [2017](https://www.tophertimzen.com/blog/BSidesPDXCTF2017/) blog post

> Around the time DEF CON rolled around, I was sitting at a Cabana at the Flamingo and ran into [CornflakeSavage](https://twitter.com/CornflakeSavage). I had previously seen what he and his team had done for the [BSidesSF CTF](https://github.com/BSidesSF/ctf-2017-release) and was inspired by the infrastructure decisions. He also authored a great blog article explaining some challenges of Docker and k8s for CTF which is viewable [here](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0). The TLDR of that blog article is that Docker did not necessarily work that well in the model as intended due to the fact we are giving competitors Remote Code Execution (RCE) vulnerabilities that are expected to grant them a shell in the container.  

We will be creating all of our challenges using `docker` and they must be deployable locally with `docker compose` as well as to an arbitrary cloud provider using `k8s`. 

## Directory Structure for Challenge Creators

Each challenge will contain the following. Note that * are optional, depending on the challenge.

```
Challenge (category/pointValue-name)
| - deployment*
| - distFiles
| - solution
| - src
| - README.md
```

Each challenge needs to have

- distFiles: What files are distributed to the competitor 

- solution: A `README.md` with a full walkthrough of solving the challenge as well as a solvable script, if applicable. See [here](https://github.com/BSidesPDX/CTF-2018/tree/master/pwn-re/100-goxor/solution) as an example

- src: All of the source code used to make the challenge, the dockerfile (if applicable), the `flag` file as well as a `Makefile` (if applicable).

- README.md: A RAEDME.md containing a title, description, deployment instructions and the challenge text that the competitor will see, as well as the flag. This is done so I can populate the scoreboard quickly. 

The optional folders are

- deployment: If this challenge runs with `docker` and will be deployed to `k8s`, it needs a `Makefile` and a `service.yml` and a `deploy.yml` that will be used. 

## Directory Structure for Hosting

```
Challenge Category
Challenge Category
LICENSE
Makefile
README.md
concepts.txt
docker-compose.yml
```

These files are

- Challenge Category: There are challenge categories such as forensics, web, shellcode, etc

- LICENSE: Apache2 source license

- README.md: A README to describe the CTF, show the challenges in table form, give kudos, talk about local deployment and how to do it, as well as deploy to the cloud. 

- [docker-compose.yml](https://github.com/BSidesPDX/CTF-2018/blob/master/docker-compose.yml): Used during `docker-compose build && docker-compose up -d` to deploy all of your docker containers

- [concepts.txt](https://github.com/BSidesPDX/CTF-2018/blob/master/concepts.txt): The intent of the CTF challenges as well as tracking progress on each one. They are tracked by category and then by `symbol` `point value` - `challenge name` with the symbols being `* = complete with solution, `+ = challenge written, needs solution/writeup`. 


You're going to want to add each dockerfile that gets committed to the compose yml in order to stand up all docker images locally for local deployment as well as testing. Some challenges will also need to be built, so add those to the Makefile as well. Look at the [2018](https://github.com/BSidesPDX/CTF-2018) CTF for how this looks. I'll explain more below. 

# Writing a Challenge

So, you want to write a challenge? The first step is to write your challenge idea in `concepts.txt`, which will be used to track if the challenge is completed or not, and approved by the CTF hosts. An example of this fully filled out is in `https://github.com/BSidesPDX/CTF-2018/blob/master/concepts.txt`

We're going to write a `pwn` 200 level challenge called `secureshell`. 

{% highlight bash %}

{ bsides-ctf-framework } HEAD > cat concepts.txt                                                         
* = complete with solution                                                                               
+ = challenge written, needs solution/writeup                                                            
                                                                                                         
-- pwn --                                                                                                
                                                                                                         
200 - secureshell - x64 Linux binary.  Asks for username and password, if both are correct, it launches a
 shell.  The username is hardcoded, however, the password is read from a file.  A strfmt vuln ca be used 
to leak this password.            
{% endhighlight %}

Once that is done, commit it up and talk to the CTF organizers for approval. 

{% highlight bash %}
{ bsides-ctf-framework } HEAD > git add concepts.txt 
{ bsides-ctf-framework } HEAD > git commit -m "Adding pwn 200 concept"
[master (root-commit) 8c955bf] Adding pwn 200 concept
 1 file changed, 6 insertions(+)
 create mode 100644 concepts.txt
{ bsides-ctf-framework } master > 
{% endhighlight %}

Once your challenge is approved, you'll want to copy the above directory structure into your challenge category as well as point value it is worth. We know this is going to be a challenge that requires docker, so we're going to also create our deployment folder. 

{% highlight bash %}
{ bsides-ctf-framework } HEAD > cd pwn 
{ pwn } HEAD > mkdir 200-secureshell
{ pwn } HEAD > cd 200-secureshell
{ 200-secureshell } master > mkdir deployment
{ 200-secureshell } master > mkdir solution
{ 200-secureshell } master > mkdir src
{ 200-secureshell } master > 
{% endhighlight %}

Now let's write the challenge. We have the concept already, so let's translate it into source. Once you've done that, you will wind up with some source files, and potentially a Makefile to build the binary.

{% highlight bash %}
{ src } master > git add password.txt 
{ src } master > git add Makefile
{ src } master > git add flag.txt
{ src } master > git add secureshell.c
{ src } master > git commit -m "Source and makefile for pwn200"
[master f02b2b6] Source and makefile for pwn200
 4 files changed, 70 insertions(+)
 create mode 100644 pwn/200-secureshell/src/Makefile
 create mode 100644 pwn/200-secureshell/src/password.txt
 create mode 100644 pwn/200-secureshell/src/secureshell.c
 create mode 100644 pwn/200-secureshell/src/flag.txt
{ src } master > 
{% endhighlight %}

We will also need this binary to run inside of a docker container. To do this, we've been using initd the last few years so we'll need a service file such as [this](https://github.com/tophertimzen/bsides-ctf-framework/blob/master/pwn/200-secureshell/src/secureshell.service)

We will also need a `Dockerfile` that we can deploy this challenge with. To do so, make a Dockerfile and add the binary and the service file to it, as well as install any dependencies. At this point, you'll also need to expose the port you want the challenge to use... in our case, we are using port `7100/tcp`. The Dockerfile for this challenge is [here](https://github.com/tophertimzen/bsides-ctf-framework/blob/master/pwn/200-secureshell/src/Dockerfile)

{% highlight bash %}
{ src } master > git add Dockerfile 
{ src } master > git add secureshell.service 
{ src } master > git commit -m "Adding docker file for pwn200"
[master 725a530] Adding docker file for pwn200
 2 files changed, 41 insertions(+)
 create mode 100644 pwn/200-secureshell/src/Dockerfile
 create mode 100644 pwn/200-secureshell/src/secureshell.service
{ src } master > 
{% endhighlight %}

With the challenge written, we need a README for it at the top level. A README will be structured as following

```
# <Challenge Category> <Point Value> - <Name>

## Description

Talk about what the challenge does and if the challenger will be provided anything

## Deployment

If anything needs to be done to deploy it

## Challenge

Description of the challenge for the leaderboard as well as the flag
```

Pwn200 would look like

```
# pwn 200 - customshell

## Description

Asks for username and password, if both are correct, it launches a shell.  The username is hardcoded, however, the password is read from a file.  A strfmt vuln can be used to leak this password.

Provide user with binary

## Deploy

1. Create `password.txt` file

## Challenge

I made my own shell, it's very secure.

flag: BSidesPDX{ayy_lma0_my_5h3ll_i5_n0t_v3ry_s3cur3}
```

We also need a solution for it as well as a full write up. Make sure your challenge can be solved automatically with a script, and if not what steps need to be done to solve it in the README. See [here](https://github.com/tophertimzen/bsides-ctf-framework/tree/master/pwn/200-secureshell/solution) for an example of pwn200.

Once you've confirmed the challenge is working in your `Dockerfile` and is solvable we need to add it to the `docker-compose.yml` back at the top level directory. Also, we have a Makefile to build our pwn200 binary and that needs to be added to the top level `Makefile`

{% highlight bash %}
{ bsides-ctf-framework } master > cat docker-compose.yml 
# pwn

secureshell:
    build: ./pwn/200-secureshell/src
    ports:
        - 7100:7100
    security_opt:
        - seccomp:unconfined
{ bsides-ctf-framework } master > git add docker-compose.yml 
{ bsides-ctf-framework } master > git commit -m "Adding pwn200 to compose"
[master 493a1f2] Adding pwn200 to compose
 1 file changed, 8 insertions(+)
 create mode 100644 docker-compose.yml

{ bsides-ctf-framework } master > cat Makefile 
target: pwn

pwn:
        make -C ./pwn/200-secureshell/src
{ bsides-ctf-framework } master > git add Makefile 
{ bsides-ctf-framework } master > git commit -m "Add pwn200 to makefile"
[master 1419eb0] Add pwn200 to makefile
 1 file changed, 4 insertions(+)
 create mode 100644 Makefile
{ bsides-ctf-framework } master > 
{% endhighlight %}

# Deploying to the Cloud

WIP

Lastly, let's make a `deployment` folder for the challenge and make sure it works in `k8s`. This is more for the challenge organizer to take care of, but the deployment files are <HERE> and are easily changed challenge by challenge. 

You will need to adjust the following in the `Makefile`

- REGISTRY: the organization on dockerhub

- DOCKER_IMAGE: What to call the docker file. Should be <challengeCategoryPoints>

You will need to adjust the following in the `deploy.yaml`

- name: What to call the challenge. Should be <challengeCategoryPoints> as in the `Makefile`

- Any extra authentication roles

You will need to adjust the following in the `service.yaml`

- targetPort, port: what ports to expose

- name: the name of the service

- app: the name of the app

# Conclusion

WIP

# Links

[2018 CTF](https://github.com/BSidesPDX/CTF-2018)

[2018 OMSI CTF](https://github.com/BSidesPDX/OMSI-CTF-2018)

[2017 CTF](https://github.com/BSidesPDX/CTF-2017)