######################################################### 
#         Powershell Remote Support Tool V1.1           # 
#                Created By: Justin Lund                # 
#             https://github.com/Justin-Lund/           # 
######################################################### 

Set-ExecutionPolicy Bypass
$host.ui.RawUI.WindowTitle = “Remote Support Tools”


function Get-Menu {     
    Clear-Host 
    "  /----------------------\" 
    "  |     REMOTE TOOLS     |" 
    "  \----------------------/" 
    ""
    "1) Launch CMRC"
    "2) Launch Active Directory"
    "3) Launch PowerShell"
    ""

    "4) Find User Account Information" 
    "5) Check Currently Logged On User"
    "6) Find Computer Information"
    ""

    "7) Get List of Installed Programs"
    "8) Access C:\ of Remote Computer"
    "9) Ping a Device"
    
    "10) Invoke Group Policy Update"
    "11) Map Network Drive"
    "12) Fix Printer Issues"
    "13) Fix Failing Updates"
    ""

    "X) Exit The program"
    ""

    $MenuSelection = Read-Host "Enter Selection" 
    Get-MenuBackend
} 


function Pause ($Message="Press any key to continue..."){ 
    "" 
    Write-Host $Message 
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
}  


function Test-Ping {
#Ensure computer is online/accessible
ping $ComputerName -n 1 | Out-Null
if ($LASTEXITCODE -eq 0)
    {
    }
Else
    {
    Write-Host "Unable to reach computer"
    Pause
    Get-Menu
    }
}


function Test-User {
#Verify Username
$Username = Get-ADUser -LDAPFilter "(sAMAccountName=$Username)"
If ($Username -eq $Null)
    {
    Write-Host ""
    Write-Host "User does not exist in AD"
    Pause
    Get-Menu
    }
Else
    {
    }
}


function Test-UserProfile {
    $PathTest = Invoke-Command -Computer $ComputerName -ScriptBlock {Test-Path "C:\Users\$Using:Username"}
    If ($PathTest -eq $True)
        {
        }
    Else
        {
    Write-Host ""
    Write-Host "User does not have a profile on this computer"
    Write-Host ""

    Pause
    Get-Menu
    }
}


function Test-DriveLetter {

    $RegPathHKU = "HKU:\$SID\Network\$NetworkDriveLetter"
    $RegPathTest = Invoke-Command -Computer $ComputerName -ScriptBlock {New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null; Test-Path "$Using:RegPathHKU"; Remove-PSDrive HKU}

    If ($RegPathTest -eq $False)
        {
        }
    Else
        {
        Write-Host ""
        Write-Host "User already has this drive letter mapped"
        Write-Host ""

        Pause
        Get-Menu
    }
}


function User-Logout {
    $LogoutSession = {
         $ErrorActionPreference = 'Stop'
 
         try {
             ## Find all sessions matching the specified username
             $Sessions = quser | Where-Object {$_ -match $Using:Username}

             ## Parse the session IDs from the output
             $SessionIDs = ($Sessions -split ' +')[2]
             Write-Host "Found $(@($SessionIDs).Count) user login(s) on computer."

             ## Loop through each session ID and pass each to the logoff command
             $sessionIDs | ForEach-Object {
                 Write-Host "Logging off $Using:Username..."
                 logoff $_
             }
         } catch {
             if ($_.Exception.Message -match 'No user exists') {
                Write-Host "The user is not logged in."
                Write-Host ""
                Pause
                Get-Menu
             } else {
                Write-Host "The user is not logged in."
                Write-Host ""
                Pause
                Get-Menu
             }
         }
     }
    Invoke-Command -Computer $ComputerName -ScriptBlock $LogoutSession
}


function Create-NetworkShare {
    #Create the registry entries for the network drive

    Invoke-Command -Computer $ComputerName -ScriptBlock {
        #Create the registry key for the network share
        echo n | Reg Add $Using:RegistryPath

        #Set the network path value
        echo n | Reg Add $Using:RegistryPath /v RemotePath /t REG_SZ /d $Using:NetworkPath | Out-Null

        #Set the remaining values
        echo n | Reg Add $Using:RegistryPath /v ConnectFlags /t REG_DWORD /d 0 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ConnectionType /t REG_DWORD /d 1 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v DeferFlags /t REG_DWORD /d 4 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ProviderFlags /t REG_DWORD /d 1 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ProviderName /t REG_SZ /d "Microsoft Windows Network" | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ProviderType /t REG_DWORD /d 131072 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v UserName /t REG_DWORD /d 0 | Out-Null
        Write-Host ""
    }
}


function Get-MenuBackend { 
    Clear-Host 
    switch ($MenuSelection){ 


        1 { #Launch CMRC 
			start "C:\SCCM 2012 - Remote Control App\CmRcViewer.exe"
			 
            Get-Menu          
          } 


        2 { #Launch Active Directory
            start C:\Windows\System32\dsa.msc
			
            Get-Menu
          } 
           

        3 { #Launch PowerShell
            start PowerShell
			
            Get-Menu   
          }


        4 { #Find User Account Information
			$Username = Read-Host "Please enter a username"
			""
			
            net user $Username /domain | findstr /i /c:"User name" /c:"Full Name" /c:"Comment" /c:"Account Active" /c:"Account Expires" /c:"Password Last Set" /c:"Password Expires" /c:"Password changeable" /c:"Last logon"
			
			Pause
			Get-Menu
          } 
           

        5 { #Check Currently Logged On User
			$ComputerName = Read-Host "Please enter a computer name or IP" 
	
			""
			Test-Ping

            gwmi -computer $ComputerName Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"} 
			
            Pause 
            Get-Menu        
          } 
           

        6 { #Find Computer Information
			$ComputerName = Read-Host "Please enter a computer name or IP" 

            ""
			Test-Ping

            systeminfo /s $ComputerName | findstr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
			
            Pause 
            Get-Menu           
          } 
           

        7 { #Get List of Installed Programs
			$ComputerName = Read-Host "Please enter a computer name or IP" 

			""
            Test-Ping
			
			gwmi -computer $ComputerName Win32_Product | Sort-Object Name | Format-Table Name,Vendor,Version 
		
            Pause 
            Get-Menu
          } 
		  

        8 { #Access C:\ of Remote Computer"
		    $ComputerName = Read-Host "Please enter a computer name or IP"

			""
            Test-Ping
			
            Invoke-Item \\$ComputerName\c$
			
			Pause
			Get-Menu
          } 

           
        9 { #Ping a Device
			$ComputerName = Read-Host "Please enter a computer name or IP" 	
			""
			
            ping $ComputerName
            Pause 
            Get-Menu          
          }         
           

        10 { #Invoke Group Policy Update
			$ComputerName = Read-Host "Please enter a computer name or IP" 

			""
            Test-Ping
			
            Invoke-GPUpdate -Computer $ComputerName -Force
            
			Pause 
            Get-Menu           
          } 


		11 { #Map Network Drive
            $ComputerName = Read-Host "Enter the computer name"
            
            Test-Ping
            
            #Prompt User for SID, save as variable
            $Username = Read-Host "Enter the username"
            Test-User
            Test-UserProfile

            #Isolate the SID
            $SID_Messy = Get-AdUser -identity $Username | Select SID
            $SID = $SID_Messy.SID.Value


            #Save the desired shared drive letter as a variable
            do
            {
                $input="NotOK"
                # Choose Drive letter
                $NetworkDriveLetter = Read-Host "Choose a drive letter"

                # Limit Drive Letter to one character
                if ($NetworkDriveLetter -notmatch "^[A,B,D-Z]$")
                {
                    Write-Host ""
                    Write-Host "Please choose a drive letter" -ForegroundColor Red
                    Write-Host ""
                    $input="NotOK"
                }

                else
                {
                    $input="ok"
                }
            }
            while($input -ne "ok")

            #Convert any input to Upper Case
            $NetworkDriveLetter = $NetworkDriveLetter.ToUpper()

            #Set the Registry Path
            $RegistryPath = "HKEY_USERS\$SID\Network\$NetworkDriveLetter"
            Test-DriveLetter


            #Save the desired network path as a variable
            $NetworkPath = Read-Host "Enter the FULL network path - eg. \\domain.loc\etc"
            

            Write-Host ""


            Create-NetworkShare

            #Logout confirmation
            $Confirmation = Read-Host "The user must log out for the drive to show up. Log user out? [Y/N]"
            While ($Confirmation -ne "Y")
            {
                If ($Confirmation -eq 'N')
                {
                Pause
                Get-Menu
                }
                $Confirmation = Read-Host "Log user out? [Y/N]"
                Write-Host ""
            }

			User-Logout

			Pause
			Get-Menu
          }


        12 { #Fix Printer Issues
			$ComputerName = Read-Host "Please enter a computer name or IP" 

			""
			Test-Ping

			Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "spooler"; Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Recurse; Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\Xerox Global Print Driver PCL6" -Recurse; Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\Xerox Global Print Driver PS" -Recurse; Start-Service "spooler"}
			
            Pause 
            Get-Menu           
          } 
		  

        13 { #Fix Failing Updates
			$ComputerName = Read-Host "Please enter a computer name or IP"

			""
            Test-Ping
			
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "wuauserv"; Stop-Service "CcmExec"; Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse ; Start-Service "wuauserv"; Start-Service "CcmExec"}
            
			Pause 
            Get-Menu           
          } 
		            

         GitHub {
                 start "http://www.github.com/Justin-Lund"
                 Get-Menu
                }


         #Colours
         Barney {
                 $Host.UI.RawUI.BackgroundColor = "DarkMagenta" 
                 $Host.UI.RawUI.ForegroundColor = "Green"
                 Get-Menu
                 }
				 
         Matrix {
                 $Host.UI.RawUI.BackgroundColor = "Black"
                 $Host.UI.RawUI.ForegroundColor = "Green"
                 Get-Menu
                 }				 

         Standard {
                 $Host.UI.RawUI.BackgroundColor = "DarkBlue"
                 $Host.UI.RawUI.ForegroundColor = "White"
                 Get-Menu
                 }	


        x {Clear-Host; exit}

        default{Get-Menu}
      }
	  
}


#--------------Start Main--------------
Get-Menu
