
# Remote Support Tools v1.6.0
*PowerShell Script for Remote Support & Administration*

This script assists with user & computer administration, launching programs, & remote troubleshooting.


## Functions

* Launch CMRC, Active Directory, & New PowerShell Windows
	- *Launching CMRC will also display the computer's systeminfo, and the user account info of the currently logged-in user.*
	- Be sure to edit the path for CMRC at the top of the script to point to your installation directory
	
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
	- *This option will stop the print spooler service, clear the target computer's printer cache, and restart the printer spooler service.*

* Fix failing updates
	- *This option will fix failing SCCM Software Center updates on a user's computer by stopping the services wuauserv & ccmexec, clearing out C:\Windows\SoftwareDistribution, and restarting the services.*

* Password Generator
	- *Type PW to access the password generator*

&nbsp;

All of the troubleshooting options work remotely, eliminating the need to remotely take control of a user's computer


![Remote Support Tools Main Menu](https://i.imgur.com/DTEaB3k.png)

![Remote Support Tools CMRC Launch](https://i.imgur.com/bls4mEL.png)


