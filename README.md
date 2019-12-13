# IT Support PowerShell Script v1.2
*PowerShell Script for Remote Support & Administration*

This script assists with user & computer administration, launching programs, & remote troubleshooting.

The options to launch programs were added for environments where they need to be run with a separate administrator account. The script can be run once at the start of the day with your admin credentials, and left open to quickly launch other programs as admin without having to re-enter your credentials every time.
If your company doesn't use CMRC for remote support, you can replace that option with whatever program you use, or remove it from the script.


## Functions
*All of the troubleshooting options work remotely, eliminating the need to remotely take control of a user's computer*

* Launch CMRC, Active Directory, & PowerShell
* Find user account information *(Displays information such as when a user's password expires)*

*Gives you the option to unlock a user if they're currently showing as locked out*

* See who's currently logged on to a computer

* Find computer information *(Displays information about a remote PC, including the last reboot time)*
* Ping a device
* Get a list of all installed programs
* Access a computer's filesystem

* Map network drives
* Invoke group policy updates

* Fix printer issues

*This option will stop the print spooler service, clear the local (for the target computer) printer cache, and restart the printer spooler service.*

* Fix failing updates

*This option will fix failing SCCM Software Center updates on a user's computer by stopping the services wuauserv & ccmexec, clearing out C:\Windows\SoftwareDistribution, and restarting the services.*


# Instructions

There are 2 options to run the script:
1) Set your execution policy to Unrestricted by running: **Set-ExecutionPolicy -ExecutionPolicy Unrestricted**

2) Save both the PowerShell script and the batch file, and use the batch file to launch the PowerShell script. Edit the batch file to point to wherever you save the PowerShell script. You can also have multiple people run off of the same script by saving the script on a network location, pointing the batch file to the script, and distributing it to multiple people.
This can be useful if you want to customize the script & continually update it, so that the main script doesn't have to be redistributed after every update.


# To Do/In Progress:

* Improved ping - provide computer-based options after pinging a device
* Ability to cancel a ping or other commands without closing the entire script
* Option to create batch files on end-user's computers - this is to provide them with the "User Command Tools" without connecting to their computer, allowing them to run local troubleshooting options themselves (https://github.com/Justin-Lund/IT-Support-Batch-Files/)
