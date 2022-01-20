Red Alert - Command & Control
==================================
<p float="left">
  <img src="https://img.shields.io/cpan/l/Config-Augeas?color=orange" alt="License: GPL-2.1" />
</p>

Red Alert is a Exploitation Framework, a network scanner that suggests potential exploits based on open services and ports. Soon aiming to be a working exploitation/auditing tool for pentester's.

https://github.com/Rodney-O-C-Melby/red-alert/

Requirements
============
In order to work correctly, Red Alert requires:

+ Python 3.10 ( https://www.python.org/ )
+ pip 20.3.4 ( https://pypi.org/project/pip/ )
+ sqlite3 3.37.2
+ nmap 7.92
+ searchsploit 4.1.3 (exploitdb)

Pip Requirements:
+ python-nmap
+ Django

Install
=================
<h3>Windows 10/11</h3>
<ul>
    <li>WSL 2 and Kali/Ubuntu are required to run on windows</li>
    <li>Turn on Windows features -> Windows Subsytem for Linux & Virtual Machine Platform.</li>
    <li>WSL 2 kernel update (x64) is included in Install/Windows/wsl_update_x64.msi to update the WSL kernel.</li>
    <li>Run the linux install inside the kali terminal.</li>
</ul>
<h3>Linux or Mac OS</h3>
Download the repository change to the relevant directory and execute the install.sh (may need to give the file execute permissions).
<p>Tested on WSL2/KALI, ARCH. Should work on any apt/pacman/brew based package managers.</p>

```
git clone https://github.com/Rodney-O-C-Melby/red-alert.git  
cd red-alert
Install/Linux/install.sh
```  

Install's all system and pip dependencies and uses setcap to give the user capture permissions without sudo. (install.sh requires sudo or root)

Usage
=================
Currently, only runs from inside the red-alert directory.
```
./redalert
```

How it works
============

<p>Red Alert allows the user to perform various network scans and get suggested possible exploits based on open services.</p> 
In the future redalert hopes to allow exploitation of a target, with records of success/failures, with tracking of active and successful exploits, and ideally with a final reporting system to enable white hat hackers, and ethical hackers, to quickly formulate a report for clients.

General features
================

+ Automatic and Manual (any) scan with Nmap.
+ Records all scans for later review, and has a quick delete all scans feature.
+ Integrated with 

Where to get help
=================

Red Alert is designed to be an intuitive user experience, no help or guidance should be necessary.

If you find a bug, fill a issue : https://github.com/Rodney-O-C-Melby/red-alert/issues

How to help out the Red Alert project
==============================

You can :

+ Send bugfixes, and patches.
+ Talk about red alert.

Licensing
=========

Red alert is released under the GNU General Public License version 2.1 (the GPL).
  Source code is available on <a href="https://github.com/Rodney-O-C-Melby/red-alert/" alt="Github">Github</a>.

Created by Rodney O. C. Melby.

Disclaimer
==========

Red Alert is cybersecurity software. It performs a scan of the provided targets network.

It is the end user's responsibility to obey all applicable local laws.

Developers and people involved in the Red Alert project assume no liability and are not responsible for any misuse or damage caused by this program.
