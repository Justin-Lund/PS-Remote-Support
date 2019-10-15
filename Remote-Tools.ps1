######################################################### 
#         Powershell Remote Support Tool V1.0           # 
#                Created By: Justin Lund                # 
#             https://github.com/Justin-Lund/           # 
######################################################### 

Set-ExecutionPolicy Bypass
$host.ui.RawUI.WindowTitle = “Remote Support Tools”

function Pause ($Message="Press any key to continue..."){ 
    "" 
    Write-Host $Message 
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
} 


function GetMenu {     
    Clear-Host 
    "  /----------------------\" 
    "  |     REMOTE TOOLS     |" 
    "  \----------------------/" 
    "" 
    "1) Find User Account Information" 
    "2) Unlock User Account" 
    "3) Find Computer Information" 
    "4) Check Currently Logged On User" 
    "5) Ping a Device"
    "6) Launch Active Directory" 
    "7) Launch CMRC" 
    "8) Launch CMD" 
    "9) Launch PowerShell" 
    "10) Get List of Installed Programs"
    "11) Fix Printers" 
    "12) Fix Failing Updates" 
    "13) Invoke Group Policy Update"
	"14) Access C:\ of Remote Computer"
    ""
    "X) Exit The program" 
    "" 
    $MenuSelection = Read-Host "Enter Selection" 
    GetInfo 
} 
 
 
function GetInfo{ 
    Clear-Host 
    switch ($MenuSelection){ 
	
        1 { #User Account Information
			$username = Read-Host "Please enter a username"
			""
			
            net user $username /domain | findstr /i /c:"User name" /c:"Full Name" /c:"Comment" /c:"Account Active" /c:"Account Expires" /c:"Password Last Set" /c:"Password Expires" /c:"Password changeable" /c:"Last logon"
			
			Pause
			GetMenu
          } 
           
        2 { #Unlock Account
			$username = Read-Host "Please enter a username"
			""
			
            Unlock-ADAccount -Identity $username
			
			Pause
			GetMenu
          } 
           
        3 { #System Information
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
            systeminfo /s $compname | findstr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
			
            Pause 
            GetMenu           
          } 
           
        4 { #Current User
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
            gwmi -computer $compname Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"} 
			
            Pause 
            GetMenu        
          } 
           
        5 { #Ping
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
            ping $compname
            Pause 
            GetMenu          
          }         
           
        6 { #Launch Active Directory
            start C:\Windows\System32\dsa.msc
			
            GetMenu
          } 
           
        7 { #Launch CMRC 
			start "C:\SCCM 2012 - Remote Control App\CmRcViewer.exe"
			 
            GetMenu          
          } 
           
        8 { #Launch CMD
            start cmd
			
            GetMenu         
          } 
         
        9 { #Launch Powershell
            start PowerShell
			
            GetMenu           
          } 
           
        10 { #Get List of Installed Programs
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
			gwmi -computer $compname Win32_Product | Sort-Object Name | Format-Table Name,Vendor,Version 
		
            Pause 
            GetMenu
          } 
		  
        11 { #Fix Printers
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
			Invoke-Command -ScriptBlock {Stop-Service "spooler"; Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Recurse ; Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\Xerox Global Print Driver PCL6" -Recurse; Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\Xerox Global Print Driver PS" -Recurse; Start-Service "spooler"} -ComputerName $compname
			
            Pause 
            GetMenu           
          } 
		  
        12 { #Fix Failing Updates
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
            Invoke-Command -ScriptBlock {Stop-Service "wuauserv"; Stop-Service "CcmExec"; Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse ; Start-Service "wuauserv"; Start-Service "CcmExec" } -ComputerName $compname
            
			Pause 
            GetMenu           
          } 
		  
        13 { #Group Policy Update
			$compname = Read-Host "Please enter a computer name or IP" 	
			""
			
            Invoke-GPUpdate -Computer $compname -Force
            
			Pause 
            GetMenu           
          } 
		  
		 14 { # Open C:\ On Remote Computer
		 $compname = Read-Host "Please enter a computer name or IP" 	
			""
			
            Invoke-Item \\$compname\c$
			
			Pause
			GetMenu
          } 

        x {Clear-Host; exit}
        default{GetMenu}
      }
	  
}

#---------Start Main--------------
GetMenu