---
title: "S4nct1m0ny bi0s CTF 2025 Writeup"
date: 2024-10-10
draft: false
tags: ["CTF", "writeup", "DFIR", "macOS", "Memory-forensics", "Malware-analysis"]
---

# S4nct1m0ny

![cover-image](images/Amazing-Spider-Man-317-cover.avif)

### Challenge Description
Peter Parker, the Daily Bugle’s star photographer and secretly Spider-Man, exposed Eddie Brock’s fake Spider-Man photos, earning J. Jonah Jameson’s praise. When Eddie begged for forgiveness, Peter snapped, “You want forgiveness? Get religion.” Humiliated, Eddie—now bonded with Venom—plotted his revenge. Recently, Peter faced performance issues with his laptop and sent it in for service. Upon its return, he noticed something was off. His Spider-Sense tingled — someone had tampered with it. Help Peter analyse the compromised system

**Challenge File**:
+ [Primary Link](https://drive.google.com/file/d/1f8wWkLfwaMpSRcq-Gua8hdcmPQcabpOB/view?usp=sharing)
+ [Mirror Link](https://mega.nz/file/5ClWnLAK#MBTjnlzVwAmK3hfNUp2FoB0rE7HHmeLiHdtPhbcnZPY)

**MD5 Hash**: 
c962ed1ae53f2003658caa07d47d33eb

### Writeup

We have been presented with a .raw file whose size is 6.45 GB upon a small peek in the hex editor we can confirm that the given file indeed is a memory dump

Q1/15) What is the OS version of the compromised system?
Format: *OS_version_number*

well, for this we were asked to find the operating system and version the of the compromised system from which the memory dump was acquired, so intially we can do the `banners.Banners` from volatility 3 :
![banners.Banners output](images/1.png)
ok when u search online for this kernel version u get :
![](images/2.png)

https://en.wikipedia.org/wiki/OS_X_El_Capitan

also when we can use volatility 2 determine the profile, since we already know its a macOS operating system we can the plugin `mac_get_profile`:

![mac_get_profile output](images/3.png)
well from the above we can conclude that the answer to the first question is `OS_X_El_Capitan_10.11.6` or `macOS_El_Capitan_10.11.6` as it was rebranded later  moving on to the next question

Q2/15) What is the hostname of the compromised system?
Format: *hostname*

To extract the hostname from the macOS El Capitan memory dump, I developed a custom Volatility 2 plugin. The hostname is a critical piece of information in forensic investigations as it helps identify the specific machine that was compromised. Volatility 2's built-in Mac plugins don't include a hostname extraction tool. However, the macOS kernel stores the system hostname in global variables that persist in memory:
- `_hostname` - Contains the actual hostname string
- `_hostnamelen` - Stores the length of the hostname (32-bit integer)
By leveraging Volatility's symbol resolution capabilities, we can locate these kernel variables directly in the memory dump without needing to search through potentially unreliable process memory or parse file system artifacts.
[...content truncated for brevity...]