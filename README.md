
# Remote Support Tools v1.6.0
*PowerShell Script for Remote Support & Administration*

This script assists with user & computer administration, launching programs, & remote troubleshooting.

All of the troubleshooting options work remotely, eliminating the need to remotely take control of a user's computer.

## Main Functions

* Launch CMRC, Active Directory, & New PowerShell Windows
	- *Be sure to edit the path for CMRC at the top of the script to point to your installation directory*
	- *Launching CMRC will also display the computer's systeminfo, and the user account info of the currently logged-in user.*

* Find user account information (such as password expiry date)
	- *Gives you the option to unlock a user if they're currently showing as locked out*

* Find computer information (such as last reboot time)
* Get a list of all installed programs
* Map network drives

* Transfer [User Command Tools batch file](https://github.com/Justin-Lund/IT-Support-Batch-Files/) to user's computer - this tool gives the user some local troubleshooting options

* Clear printer cache & restart print spooler service
	
* Clear failed updates
	- *This option will fix failing SCCM Software Center updates on a user's computer by stopping the services wuauserv & ccmexec, clearing out C:\Windows\SoftwareDistribution, and restarting the services.*

&nbsp;


**See the screenshots below for the full overview of the script's functionalities**

![Remote Support Tools Main Menu](https://i.imgur.com/MuiUMVU.png)

![Remote Support Tools Unlisted Options](https://i.imgur.com/p9FRgbc.png)


## Editing the Script

The script is separated into functions, and is best navigated in the PowerShell ISE, with the functions collapsed (Ctrl + M)

Function descriptions have been added on the closing braces, for easy navigation when collapsed (see screenshot below)

If you create a new function, you must add it to the "Get-MenuBackend" switch

If you come up with something useful to add to the script, please feel free to send a pull request!

![Remote Support Tools Powershell ISE](https://i.imgur.com/wJwG0JM.png)
