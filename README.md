
# Remote Support Tools v1.5.3
*PowerShell Script for Remote Support & Administration*

This script assists with user & computer administration, launching programs, & remote troubleshooting.

## Functions

* Launch CMRC, Active Directory, & PowerShell
	- *Launching CMRC will also display the computer's systeminfo, and the user account info of the currently logged-in user.*
	
* See who's currently logged on to a computer
* Find user account information *(Displays information such as when a user's password expires)*
	- *Displays information such as when a user's password expires*
	- *Gives you the option to unlock a user if they're currently showing as locked out*

* Find computer information
* Get a list of all installed programs
* Access a computer's file system
* Invoke group policy update
* Map network drives

* Transfer [User Command Tools batch file](https://github.com/Justin-Lund/IT-Support-Batch-Files/) to user's computer - this tool gives the user some local troubleshooting options

* Fix printer issues
	- *This option will stop the print spooler service, clear the local (for the target computer) printer cache, and restart the printer spooler service.*

* Fix failing updates
	- *This option will fix failing SCCM Software Center updates on a user's computer by stopping the services wuauserv & ccmexec, clearing out C:\Windows\SoftwareDistribution, and restarting the services.*

*All of the troubleshooting options work remotely, eliminating the need to remotely take control of a user's computer*

![Remote Support Tools Main Menu](https://i.imgur.com/DTEaB3k.png)

![Remote Support Tools CMRC Launch](https://i.imgur.com/bls4mEL.png)


*The options to launch programs were added for environments where they need to be run with a separate administrator account. The script can be run once at the start of the day with your admin credentials, and left open to quickly launch other programs as admin without having to re-enter your credentials every time.
If your company doesn't use CMRC for remote support, you can replace that option with whatever program you use, or remove it from the script.*

# Instructions

* Edit the path for CMRC at the top of the script to point to your installation directory

There are 2 options to run the script:
1) Set your execution policy to Unrestricted by running: **Set-ExecutionPolicy -ExecutionPolicy Unrestricted**

2) Save both the PowerShell script and the batch file, and use the batch file to launch the PowerShell script. Edit the batch file to point to wherever you save the PowerShell script. You can also have multiple people run off of the same script by saving the script on a network location, pointing the batch file to the script, and distributing it to multiple people.
This can be useful if you want to customize the script & continually update it, so that the main script doesn't have to be redistributed after every update.
