#################################################################################################
Write-Host $(Get-Date)
Write-Host -ForegroundColor Yellow "Setting up Environment..."
$env:path += ";n:\Scripting"
$env:path += ";n:\Scripting\Released"
$env:path += ";n:\Scripting\Downloaded"
$env:path += ";C:\Program Files\Microsoft\Exchange Server\V15\scripts"
#
psedit "n:\Scripting\_PowerShellFavorites.ps1"
#
cd "C:\Users\andern\Downloads"
# Constrained Language
If ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SESSION MANAGER\Environment" -Name __PSLockdownPolicy).__PSLockdownPolicy -ne 0) {
    Write-Warning "Please elevate to set Constrained Language and Execution Policy"
    Read-Host "Press Enter to continue"
    Start-Process powershell -verb RunAs {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SESSION MANAGER\Environment' -Name __PSLockdownPolicy -Value 0
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value Unrestricted
    }
    Write-Warning "Settings have changed, please resart this session."
    Exit
}
# Execution Policy
If ((Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy).ExecutionPolicy -ne "Unrestricted") {
    If ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value Unrestricted
    } Else {
        Write-Warning "Please elevate to set Execution Policy"
        [System.Windows.MessageBox]::Show("Please elevate to set Execution Policy",$Script_Title,0,64)
        Start-Process powershell -verb RunAs "Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value Unrestricted"
    }
    Write-Warning "Settings have changed, please resart this session."
    Exit
}


#################################################################################################
Write-Host -ForegroundColor Yellow "Importing Modules..."
#################################################################################################
Import-PSSession (New-PSSession -name N8Exch4 -ConfigurationName Microsoft.Exchange -Authentication Kerberos -ConnectionUri http://exch4.southside.local/PowerShell/) -AllowClobber
#################################################################################################
        ## SCCM Module ##
# Site configuration
$SiteCode = "SSB" # Site code 
$ProviderMachineName = "sccm01.southside.local" # SMS Provider machine name
# Customizations
$initParams = @{}
#$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
#$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors
# Do not change anything below this line
# Import the ConfigurationManager.psd1 module 
if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}
# Connect to the site's drive if it is not already present
if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
}
# Set the current location to be the site code.


#################################################################################################
Write-Host -ForegroundColor Yellow "Loading Functions..."
#################################################################################################
$StartupVariables = Get-Variable
$StartupVariables += Get-Variable StartupVariables
Set-Variable StartupVariables -Option ReadOnly
#set-variable StartupVariables -Option None -force
function Reset-Variables {
    Write-Host -ForegroundColor Yellow "$($StartupVariables.count) variables loaded at startup are being skipped. Check `$StartupVariables to view."
    $a = Get-Variable | Where-Object {$_.Name -notin $StartupVariables.Name}
    if ($a) {
        $a
        $a | ForEach-Object {Remove-Variable -Name $_.Name -scope 1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue}
        Write-Host "`n`r$($a.count) variables have been deleted..."
    } else {
        Write-Host -ForegroundColor Red "No variables found."
    }    
} #End Function
#################################################################################################
function Prompt {
$Script_Title = "Prompt" #N8's custom PS Prompt
$Script_Author="Nathan Anderson"
$Script_Version="1.0"
<#-----------------------------------------------------------------------------
Syntax: 
    Install in your PS profile to customize your prompt
Purpose:
    Custom prompt to timestamp commands.
Version Info:
    1.0 2/22/2023 FIRST!
	
-----------------------------------------------------------------------------#>
    $dateTime = get-date -Format HH:mm:ss.ff
    $currentDirectory = $(Get-Location)
    write-host -ForegroundColor White "$dateTime $(Convert-Path $currentDirectory)>" -NoNewline
    return " "
} #End Function
#################################################################################################
<#
Function Title: Sign-Script
Function Author: Nathan Anderson
Function Version: 1.0

Syntax: 
    Sign-Script [-FilePath <Path to Script File>]

Purpose:
    Digitally sign your Powershell script with your personal Code Signing certificate. Valid certificate must be installed in personal store.
 
Version Info:
    9/4/2018 1.0 First Released.

Next:
    sign all ps1 scripts in a folder! (Maybe pipe path from get-childitem? Maybe just provide path to command?)
    add option to select cert if multiple are found
             
#>
function Sign-Script
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    $Timestamp_Server = "http://timestamp.comodoca.com/authenticode"
    $Personal_Cert = $null
    $Personal_Cert = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)
    IF (($Personal_Cert) -and !($Personal_Cert -is [array])) {
        Set-AuthenticodeSignature -FilePath $FilePath -certificate $Personal_Cert -TimestampServer $Timestamp_Server
    } ELSE {
        Write-Host "Error getting personal certificate. Get-ChildItem returned either null or mulitple results."
    }
}
#################################################################################################
function Get-LastLoggedIn (){
    Param (
        [Parameter(Mandatory=$true)]$Machines,
        [Switch]$Fast,
        [Switch]$All
    )
    #Delcares
    $SCCMCurrentLogonUser_msg = "User currently logged in according to SCCM." 
    $SCCMLastLogonUser_msg = "Last Logged on user according to SCCM."
    $WMIUser_msg = "User is currently logged in on Console session."
    $WMIExplorer_msg = "User is currently logged in remotely (session may be locked)."
    $ProfileFolder_msg = "Profile folder with most recent LastAccessTime."
    $NoPingResponse_msg = "No ping response."
    $UnableToDetermine_msg = "Unable to determine last user."

    If ($Machines.count -gt 1) {$StartTime=get-date}
    $ErrorActionPreference = 'SilentlyContinue'
    $Ob_Arr=@()
    $PSDrive_Backup = Get-Location
    ForEach ($Machine in $Machines){
        If ($Machines.count -gt 1) {
            $Count+=1
            Write-Progress -Activity "Get-LastLoggedIn" -Status "($Count of $($Machines.count))" -CurrentOperation $Machine -PercentComplete ($Count/$Machines.count*100) -Id 5 -ParentId 1
        }
#Just get all profile folders if doing -All
        If ($All) {
            $PingResults = $null
            $PingResults = Test-Connection -count 1 $Machine
            If ($PingResults){
                if ($PSDrive_Backup.Provider.Name -eq "CMSite"){
                    Set-Location $((get-psdrive|? {$_.Provider -like "*FileSystem*"}|Select Name -first 1).Name + ':')
                }
                $Folder=Get-ChildItem "\\$Machine\c$\Users" |Sort-Object LastAccessTime,LastWriteTime -Descending|Select-Object Name,LastAccessTime,LastWriteTime
            }
            Else {
                Write-Error "Ping did not succeed.";Return $PingResults
            }
            Return $Folder
        }
        $Username = $null
        $UserMethod = $null
#Time to try some offline things...
        #Try to get user via SCCM
        If (Get-Module ConfigurationManager) {
            Set-Location "$($SiteCode):\" @initParams
            $SCCM_Device = Get-CMDevice -name $Machine
            If (($SCCM_Device).CurrentLogonUser) {
                $Username = ($SCCM_Device).CurrentLogonUser.replace("SOUTHSIDE\","").replace("southside\","")
                $UserMethod = $SCCMCurrentLogonUser_msg
            } Else {
                If (($SCCM_Device).LastLogonUser) {
                    $Username = ($SCCM_Device).LastLogonUser
                    $UserMethod = $SCCMLastLogonUser_msg
                }
            }
        } #End of SCCM module check
#Time to try some online things...
        If (!($Username) -and !($Fast)) {
            $PingResults = $null
            $PingResults = Test-Connection -count 1 $Machine
            #Try to get user via WMI (Currently logged in on console)
            If ($PingResults){
                If (!($Username)) {
                    $RPCAvail=$null
                    3/$null            #Error bump
                    $Username = (Get-WmiObject win32_computersystem -ComputerName $Machine|Select-Object username).username.replace("SOUTHSIDE\","").replace("southside\","")
                    If ($error[0] -like "*The RPC server is unavailable*") {$RPCAvail=$False}Else{$RPCAvail=$True}
                    If ($Username) {$UserMethod = $WMIUser_msg}
                }
                #Try to get user via Explorer processes
                If (!($Username) -and $RPCAvail) {    #Skip second WMI command if first one has RPC failure to avoid extra 42 sec. timeout
                    $Username = (Get-WmiObject -Class win32_process -Computername $Machine|? name -Match explorer|Sort-Object CreationDate -Descending|Select-Object -First 1).GetOwner().User
                    If ($Username) {$UserMethod = $WMIExplorer_msg}
                }
                #Try to get user via User Profile folders
                If (!($Username)){
                    $Folder=Get-ChildItem "\\$Machine\c$\Users" |Sort-Object LastAccessTime -Descending|Select-Object Name,LastAccessTime -First 1
                    $Username = $Folder.name.Replace(".000","").Replace(".001","").Replace(".002","").Replace(".southside","").Replace(".southside.000","").Replace(".southside.001","").Replace(".southside.002","").Replace(".SOUTHSIDE","").Replace(".SOUTHSIDE.000","").Replace(".SOUTHSIDE.001","").Replace(".SOUTHSIDE.002","")
                    If ($Username) {$UserMethod = $WMIExplorer_msg}
                }
            }
            Else {
                $UserMethod = $NoPingResponse_msg
            } #End of if ping / else
        } #End of not Fast (Online) checks.
#Time to build output object
        If (!$Username -and !$UserMethod) {$UserMethod = $UnableToDetermine_msg}
        $Obj=New-Object –TypeName PSObject -Property @{
            Computer=$Machine
            UserName=$Username
            SCCMPrimaryUser=$SCCM_Device.PrimaryUser
            UserGetMethod=$UserMethod
        } #End of new object hash
        $Ob_Arr+=$Obj
    } #End main for-each loop
    If ($Machines.count -gt 1){
        Write-Host -ForegroundColor Green "Run time: $((Get-Date)-$StartTime)"
        Write-Progress -Activity "Get-LastLoggedIn" -Id 5 -Completed
    }
    Set-Location $PSDrive_Backup
    Return $Ob_Arr
} #End Function
#################################################################################################
<# Function Title: Find-Computer
Function Author: Nathan Anderson
Function Version: 1.7.2
Keywords: 

Syntax: 
     Find-Computer it-infsrv57-lt
     Find-Computer 56mortge1,it-infsrv57-lt,asdfasdf
     Find-Computer (Import-Csv .\12_21_2020.csv).ComputerName
     $a = (Import-Csv .\12_21_2020.csv).ComputerName
     $a += "it-infsrv57-lt","asdfasdf","it-nathana3-lt"
     Find-Computer $a|sort-object LastLogonDate|ft Name,DistinguishedName,Enabled,IPv4Address,LastLogonDate,PasswordLastSet,whenChanged,Ping,LastUser
     Find-Computer (Get-ADComputer -Filter {operatingsystem -like "*Pro*" -and enabled -eq $true} -Properties LastLogonDate | Where { $_.LastLogonDate -lt (Get-Date).AddDays(-14) } | select -ExpandProperty name)

Purpose:
     Get pertenant details about computers that will help track them down. Originally designed for inventory / falling off the domain help.
     
     Use -Fast switch to prevent reaching out to the PC. This will limit the amount of data returned.
     
Version Info:
     1.0 - Built to help gather data on aging computers.
     1.1 4/12/2021 Updated / streamlined code and object building. Removed ping success requirement for Get-LastLoggedIn since it can now get from SCCM. Incorporated more AD user lookups and more SCCM.
     1.2 4/14/2021 Added user's department and title. Added -Fast.
     1.3 4/16/2021 Removed SCCMIsActive, added email address
     1.4 4/19/2021 Added Comptuer description and tweaked a little more speed by calling Get-LastLoggedIn -fast if the previous ping failed. Added SCCM Primary User(s).
     1.5 9/7/2021 Added additional output to relay SCCM detection and -Fast switch detection.
     1.6 2/21/2023 Removed Yellow "SCCM ConfigurationManager Module detected." and Fast mode output. Added support for using IPs too. Added variable sanitation in loop.
     1.7 2/28/2023 Moved from SCCM's LastActiveTime to CNLastOnlineTime and noted UTC. Fixed missing IP Address from adding IP support.
     1.7.1 3/1/2023 Changed test-netconnection to test-connection due to write-progress take-over.
     1.7.2 3/2/2023 Added warning if comptuer not found in AD.
	 *Can you get info from SDP? User, Department, Service Tag, asset state, last scan?
#>

function Find-Computer
{
    Param(
        [Parameter(Mandatory=$True)]$Machines,
        [Switch]$Fast
    )

    #Prerequisites
    If (!(Get-Command Get-LastLoggedIn)) {Write-Error "Prerequisite Get-LastLoggedIn is not available.";Return}
    If (!(Get-Command Get-AdComputer)) {Write-Error "Prerequisite Get-AdComputer is not available.";Return}
    If (!(Get-Module ConfigurationManager)) {Write-Warning "SCCM ConfigurationManager Module not detected. Continuing..."}
    $ErrorActionPreference = 'SilentlyContinue'
    $PSLocationBackup = Get-Location

    #Start the  main loop!
    $Obj_Arr = @()
    foreach ($Machine in $Machines) {
        Remove-Variable S,L,A,P,D,U,IPAddress -ErrorAction SilentlyContinue
        $D = Resolve-DnsName $Machine
        If ($D.NameHost) {
            $IPAddress = $Machine
            $Machine = $D.NameHost.replace('.' + $((Get-DnsClientGlobalSetting).suffixsearchlist[0]),"")
        } Else {
            $IPAddress = $D.IPAddress
        }
        #Get AD Computer Info
        If ($A = get-adcomputer -filter {name -eq $Machine} -Properties Name,DistinguishedName,Created,Enabled,LastLogonDate,OperatingSystem,Operatingsystemversion,PasswordLastSet,ManagedBy,Description) {
            $A | Add-Member –MemberType NoteProperty –Name ManagedByFullName –Value $((get-aduser $A.ManagedBy -properties DisplayName).DisplayName) -Force
        } Else {
            Write-Warning "Computer not found in AD."
        }
        #Get more info from Computer
        IF (!($Fast)) {$P = Test-Connection $Machine -count 1 -quiet -ErrorAction SilentlyContinue}
        If (Get-Module ConfigurationManager) {
            Set-Location "$($SiteCode):\" @initParams
            $S = get-cmdevice -name $Machine
            Set-Location $PSLocationBackup
        }
        #Get some user info
        IF ($Fast -or !$P) {$L = Get-LastLoggedIn $Machine -Fast}
        IF (!$Fast -and $P) {$L = Get-LastLoggedIn $Machine}
        Remove-Variable U
        $U = Get-ADUser $L.UserName -Properties DisplayName,ipPhone,Department,Description,EmailAddress
        #Build Output Object
        $Object = New-Object Psobject -Property @{
	        Name = $Machine
            ManagedBy = $A.ManagedBy
            PCDescription = $A.Description
            ManagedByFullName = $A.ManagedByFullName
            DistinguishedName = $A.DistinguishedName
            ADCreated = $A.Created
            Enabled = $A.Enabled
            PCLastLogonDate = $A.LastLogonDate
            OperatingSystem = $A.OperatingSystem
            Operatingsystemversion = $A.Operatingsystemversion
            PCPasswordLastSet = $A.PasswordLastSet
            IPAddress = $IPAddress
            PingResult = $P
            SCCMCNLastOnlineTimeUTC = $S.CNLastOnlineTime
            SCCMClientVersion = $S.ClientVersion
            MACAddress = $S.MACAddress
            SerialNumber = $S.SerialNumber
            IsVirtualMachine = $S.IsVirtualMachine
            LastUser = $L.UserName
            LastUserGetMethod = $L.UserGetMethod
            LastUserFullName = $U.DisplayName
            'PrimaryUser(s)' = $S.PrimaryUser
            Department = $U.Department
            UserDescription = $U.Description
            EmailAddress = $U.EmailAddress
            ipPhone = $U.ipPhone
        }
        $Obj_Arr += $Object
    } #End main for-each loop
    Return $Obj_Arr
} #End Function
#################################################################################################
function Wait-Connection {
Param (
    [Parameter(Mandatory=$true, Position=0)][string] $Name_Or_IP
)
$Script_Title = "Wait-Connection"
$Script_Author="Nathan Anderson"
$Script_Version="1.0"
<#-----------------------------------------------------------------------------
Syntax: 
    Wait-Connection [Host name or IP address]
    
Purpose:
    Wait until Test-Connection succeeds.
     
Version Info:
    1.0 2/2/2023
	
-----------------------------------------------------------------------------#>
while (!(Test-Connection -count 1 -Quiet $Name_Or_IP)) {
    Write-Progress -id 99 -Activity "Lost Connection" -Status "Waiting for connection..." -PercentComplete 2
}
Write-Progress -id 99 -Activity "Lost Connection" -Completed
} #End Function
#################################################################################################
function ping
{
    Param (
        [Parameter(Mandatory=$true)]$Machine,
        [switch]$Quiet
    )
$Script_Title = "ping"
$Script_Author="Nathan Anderson"
$Script_Version="1.1"
<#-----------------------------------------------------------------------------
Syntax: 
    ping [Hostname] [-Quiet]

Purpose:
    Continous ICMP with sound and clearing DNS Client Cache.

Version Info:
    1.0 6/13/2023 First try.
    1.1 7/4/2023 Added -Quiet

Next:
    If input is array, echo them all once and output chart. Ideally output goes on-screen as echos are processed.
	
-----------------------------------------------------------------------------#>
#Initialize variables
Write-Host -ForegroundColor Green "$(get-date -format HH:mm:ss.ff) Pinging $Machine."
Clear-DnsClientCache
$a = Test-Connection -count 1 $Machine
if ($a)
{$State = 0}
Else
{$State = 1}
#
While ($true)
{
    Clear-DnsClientCache
    $a = Test-Connection -count 1 $Machine -ErrorAction SilentlyContinue
    if ($a)
    {
        if (!($quiet)) {[console]::beep(500,1000)}
        if ($State -eq 0)
        {
            $State = 1
        }
    } Else {
        if (!($quiet)) {[console]::beep(500,100)}
        Write-Host -ForegroundColor Yellow "$(get-date -format HH:mm:ss.ff) Request timed out."
        if ($State -eq 1)
        {
            $State = 0
        }
    }
    $a
    If ($quiet) {sleep 1}
}
} #End Function
#################################################################################################
function Get-List {

$Script_Title = "Get-List"
$Script_Author="Nathan Anderson"
$Script_Version="1.0"
<#-----------------------------------------------------------------------------
Syntax: 
    Get-List

Purpose:
    Ability to paste a list into a variable.

Version Info:
    1.0 7/7/2023 First try.

-----------------------------------------------------------------------------#>
$Global:List = @(Read-Host "Paste in the list!" ) -split '\r\n' -split '\n\r' -split '\n' -split '\r' -split ',' -split ';' -split ' ' -split '\t'
} #End Function
#################################################################################################
function Find-ADUser {
Param(
    [Parameter(Mandatory=$True)]$User
)
$Script_Title = "Find-ADUser"
$Script_Author="Nathan Anderson"
$Script_Version="1.0"
<#-----------------------------------------------------------------------------
Syntax: Find-User <Partial displayname>
    
Purpose: Find AD user from partial search
     
Version Info:
    1.0 9/18/2023 First!
    Next: List computers they use (via SCCM?)
        Allow array input (more than one lookup at a time)?
        Add samaccountname search
        Anixis enrollment?
	
-----------------------------------------------------------------------------#>
$User = "*" + $User + "*"
$a = get-aduser -filter {displayname -like $User} -Properties *
return $a
}
#################################################################################################
function Count-Down {
    [alias("Wait")]
    Param (
        [Parameter(
            Mandatory=$true,
            Position=0
            )]
            [Int]$Seconds
    )
$Script_Title = "Count-Down"
$Script_Author="Nathan Anderson"
$Script_Version="1.0"
<#-----------------------------------------------------------------------------
Purpose:
    to Count-Down -Seconds with a progress bar.

Version Info:
    1.0 7/4/2023 First try
    Add an inturrupt so the countdown will stop when it is pressed.
	
-----------------------------------------------------------------------------#>
For ($i=$Seconds; $i -gt 0; $i--) {
	Write-Progress -Activity $Script_Title -Status $i -PercentComplete ($i / ($Seconds) * 100)
    sleep 1
}
Write-Progress -Activity $Script_Title -Completed
} #End Function
#################################################################################################

# SIG # Begin signature block
# MIIi6AYJKoZIhvcNAQcCoIIi2TCCItUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeOarFp2jgc+Z4+e5EM/9z3Ue
# Is2gghzwMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0B
# AQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNV
# BAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsx
# LjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw
# HhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEb
# MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgw
# FgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRp
# bWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDI
# GwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJNMvzRWW5
# +adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29ddSU1yVg/c
# yeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKsLgp3/A2U
# Urf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJf1bgvUac
# gr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdgaZtYClT0
# Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7nw0U1BjE
# MJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8NfwKMVPZIMC
# 1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee647BeFbG
# RCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opBJNQb/HKl
# FKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1FNsH3jYL6
# uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCCAVYwHwYD
# VR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh+GEZIA/D
# QXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8E
# STBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNB
# Q2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsG
# AQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRk
# VHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5j
# b20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0lhBGysNsq
# fSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQff+wdB+P
# xlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/EwHFhaNM
# xcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83Jb5A9f0Vy
# wRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK0z2vgwY4
# Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdlHb7qvNhC
# g0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglfjv33sVKR
# zj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4nmuWgwAxy
# h8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5PObBMLvA
# oGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE2See+wFm
# d7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kKyVRd1Llq
# dJ69SK6YMIIG7TCCBNWgAwIBAgITLgAAAAImihHGTFhRmQAAAAAAAjANBgkqhkiG
# 9w0BAQsFADAhMR8wHQYDVQQDExZTb3V0aHNpZGUgQmFuayBSb290IENBMB4XDTE3
# MDMwMjE2NDY1NFoXDTI1MDMwMjE2NTY1NFowWzEVMBMGCgmSJomT8ixkARkWBWxv
# Y2FsMRkwFwYKCZImiZPyLGQBGRYJc291dGhzaWRlMScwJQYDVQQDEx5Tb3V0aHNp
# ZGUgQmFuayBJbnRlcm1lZGlhdGUgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCfnlgy7aRsWtRENBM4rDHXqZ/uhUZtf/mtWzI2NqTnm0KJJl8ao1ap
# ls/EW0M8Ah5FHoXpucFVjmIaAVM1cEZt0olZ+uWdQR4ksFgYoVkNPKWARE/p11PB
# FQCEADU7D7MMtmCNvLSfDa658CEuH4Bwt7Jg/rbAdqyN+ZqK8t7ZwJ+BqthEQx/x
# cGbP6N0SlQJ16hsLOajkzQCkPOs+g+E6iCQHV7h6xIqeK+G+azZ4kBzmKaQvj6tH
# ROhwZqVlL72TQp6HRMPCD1eTvNPolEc+Ht3W6MDv7Wk92RUvYZL82LrmUNkG2Hy3
# VFgHb0K4381BlYaeUiNx56NGFBSzjnvHbVYYppUe6cILgosKSNktL9H7cGAP6tfo
# 8U6wY8J7agUisOEYbIFh3kMhyzsKewdnReD9pzTffEHoaMo6wlL4mvskg4iuX+Ie
# a0CMmaSEkmnvYxlyt+dbJtr62RjsCZO72tHp1IpPrI5GBBNEC5eJ548W2TToHMrx
# /9hi+86VflWTchkhfjEIZ7yiEgu4CjLPBdQB7MIkF8nrL99I5/J3VzZ6o5zMwkno
# g31aFfxWOFGiz3H7dd0REknL/Z660AIMPxPoBXJoXtPxsTnRF7Xl8BMkq/ljAtt3
# rsj5Y78SWNZZt2gshn5neY7ciNZkMp2cmMnu8vmOV6BLX9s83eJvXQIDAQABo4IB
# 4jCCAd4wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFLb+NI5ijlm8ixD+aJ34
# 1TqQSgb1MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFOmKB7ZAxkKkbtsj8OZYjiiLenLq
# MIGWBgNVHR8EgY4wgYswgYiggYWggYKGO2ZpbGU6Ly8vL1JPT1RDQS9DZXJ0RW5y
# b2xsL1NvdXRoc2lkZSUyMEJhbmslMjBSb290JTIwQ0EuY3JshkNodHRwOi8vY2Eu
# c291dGhzaWRlLmxvY2FsL2NlcnRkYXRhL1NvdXRoc2lkZSUyMEJhbmslMjBSb290
# JTIwQ0EuY3JsMIG3BggrBgEFBQcBAQSBqjCBpzBOBggrBgEFBQcwAoZCZmlsZTov
# Ly8vUk9PVENBL0NlcnRFbnJvbGwvUk9PVENBX1NvdXRoc2lkZSUyMEJhbmslMjBS
# b290JTIwQ0EuY3J0MFUGCCsGAQUFBzAChklodHRwOi8vY2Euc291dGhzaWRlLmxv
# Y2FsL2NlcnRkYXRhL1JPT1RDQVNvdXRoc2lkZSUyMEJhbmslMjBSb290JTIwQ0Eu
# Y3J0MA0GCSqGSIb3DQEBCwUAA4ICAQAf2vFJkMJY6d/a2wMSO13Br1GgKk/3FSOU
# utdrd45XyI9o5h+wg0YKwk2+WF2qaUbSNpcjc0xxpVLib1xvHmY80n/s+/CQT25T
# BIld+SkLMP1fQh0cKhkA8O0YjQvQYIxjx8BNJSR5KWC+aj06SCg89tvt/9Cl2Awv
# x614BOk3YLMrbFvaN3bBqjNj8fg07KqvtkXivl3Edfc7i942RbY1i2HeJG+8ibfR
# IO6GylPIZ5RY/BVlIM8D+VlaYQBHS3s0oBq9ZEHaq7iVS7dcqoFjJd4AsoyJlbZS
# J7l4QLHk+nsSlN34/Mc0iW1+bjobJ3z1ym+VEP8kPxD+JFAZ5BjJZf/ygAe7dZGP
# fDXGW+fPVrGfbVvmJMbf21+BBzrjWF59pUHC5A/DnLyy0jiMDJ0tyG1vCHoDTWy9
# klVWtsCCbEZLtKGJDocXmPeWdrQrJEoWypNYRSTTIQ0P01/B6Znf8ceyVMABG8PX
# +LDQGWeerwBPlh+SfJEUse0+BC5MDGYbQHjlQpsNgB56Sgqdfw+UIVVS7BP9JRdz
# une2amuS3zcprwt+0+unor3H0pW/Efh281V/U9M1kR/9Z70tY93gxGx+ewYC197b
# hFNAbpGbs2nX4XLaz1Tnjnim0K/gVGLJs3+DNF3lanRr32jwt8QyZ2xJiltI6CkY
# xhLm52/ygzCCBvUwggTdoAMCAQICEDlMJeF8oG0nqGXiO9kdItQwDQYJKoZIhvcN
# AQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUw
# IwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIzMDUwMzAw
# MDAwMFoXDTM0MDgwMjIzNTk1OVowajELMAkGA1UEBhMCR0IxEzARBgNVBAgTCk1h
# bmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwjU2Vj
# dGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCkkyhSS88nh3akKRyZOMDnDtTRHOxoywFk5IrNd7Bx
# ZYK8n/yLu7uVmPslEY5aiAlmERRYsroiW+b2MvFdLcB6og7g4FZk7aHlgSByIGRB
# bMfDCPrzfV3vIZrCftcsw7oRmB780yAIQrNfv3+IWDKrMLPYjHqWShkTXKz856vp
# HBYusLA4lUrPhVCrZwMlobs46Q9vqVqakSgTNbkf8z3hJMhrsZnoDe+7TeU9jFQD
# kdD8Lc9VMzh6CRwH0SLgY4anvv3Sg3MSFJuaTAlGvTS84UtQe3LgW/0Zux88ahl7
# brstRCq+PEzMrIoEk8ZXhqBzNiuBl/obm36Ih9hSeYn+bnc317tQn/oYJU8T8l58
# qbEgWimro0KHd+D0TAJI3VilU6ajoO0ZlmUVKcXtMzAl5paDgZr2YGaQWAeAzUJ1
# rPu0kdDF3QFAaraoEO72jXq3nnWv06VLGKEMn1ewXiVHkXTNdRLRnG/kXg2b7HUm
# 7v7T9ZIvUoXo2kRRKqLMAMqHZkOjGwDvorWWnWKtJwvyG0rJw5RCN4gghKiHrsO6
# I3J7+FTv+GsnsIX1p0OF2Cs5dNtadwLRpPr1zZw9zB+uUdB7bNgdLRFCU3F0wuU1
# qi1SEtklz/DT0JFDEtcyfZhs43dByP8fJFTvbq3GPlV78VyHOmTxYEsFT++5L+wJ
# EwIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYSBFUw
# HQYDVR0OBBYEFAMPMciRKpO9Y/PRXU2kNA/SlQEYMA4GA1UdDwEB/wQEAwIGwDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEw
# NQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
# b20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnNl
# Y3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYIKwYBBQUH
# AQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3Rp
# Z29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3Nw
# LnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBMm2VY+uB5z+8VwzJt3jOR
# 63dY4uu9y0o8dd5+lG3DIscEld9laWETDPYMnvWJIF7Bh8cDJMrHpfAm3/j4MWUN
# 4OttUVemjIRSCEYcKsLe8tqKRfO+9/YuxH7t+O1ov3pWSOlh5Zo5d7y+upFkiHX/
# XYUWNCfSKcv/7S3a/76TDOxtog3Mw/FuvSGRGiMAUq2X1GJ4KoR5qNc9rCGPcMMk
# eTqX8Q2jo1tT2KsAulj7NYBPXyhxbBlewoNykK7gxtjymfvqtJJlfAd8NUQdrVgY
# a2L73mzECqls0yFGcNwvjXVMI8JB0HqWO8NL3c2SJnR2XDegmiSeTl9O048P5RNP
# WURlS0Nkz0j4Z2e5Tb/MDbE6MNChPUitemXk7N/gAfCzKko5rMGk+al9NdAyQKCx
# GSoYIbLIfQVxGksnNqrgmByDdefHfkuEQ81D+5CXdioSrEDBcFuZCkD6gG2UYXvI
# brnIZ2ckXFCNASDeB/cB1PguEc2dg+X4yiUcRD0n5bCGRyoLG4R2fXtoT4239xO0
# 7aAt7nMP2RC6nZksfNd1H48QxJTmfiTllUqIjCfWhWYd+a5kdpHoSP7IVQrtKcMf
# 3jimwBT7Mj34qYNiNsjDvgCHHKv6SkIciQPc9Vx8cNldeE7un14g5glqfCsIo0j1
# FfwET9/NIRx65fWOGtS5QDCCCBIwggX6oAMCAQICE0wAALbVuiaYWQZAIpIAAAAA
# ttUwDQYJKoZIhvcNAQELBQAwWzEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRkwFwYK
# CZImiZPyLGQBGRYJc291dGhzaWRlMScwJQYDVQQDEx5Tb3V0aHNpZGUgQmFuayBJ
# bnRlcm1lZGlhdGUgQ0EwHhcNMjMwNzA2MTUxMzEyWhcNMjUwMzAyMTY1NjU0WjB1
# MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFglzb3V0aHNp
# ZGUxFzAVBgNVBAsMDkJyYW5jaGVzX1VzZXJzMRcwFQYDVQQLDA5fQ29tcHV0ZXIg
# RGVwdDEPMA0GA1UEAxMGQU5ERVJOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEA3USBg/lJgib88F98OQLaUUHf//tlms0JXbFi9QDXc/9tGZizeKEG3Z9I
# YwtVCXwdUscppanPLK1XAG14bz2p4oiJWenif35CHQpwJex+5i12Q6QU7+QRMDm3
# o9dJCdsmlZU8rQ3AY5ucBM9M40wz5YKCQMaE+DAurOtYcupwMJ/Z+3fZdWSZ9Lib
# HhWeUqwru14Z1fbHi0nLsen5qANGDMtRX/QNdG0qJYA/aSxMh+le6NmMPNgNo57h
# AOuhDDZoJ50xgLwVFI0rTRfKLRZ0PB9iPL3BNre0ZwKNbolIGV/gfch/zUKwhtZ8
# qiWLvlHDPUYL6kHv9JSXgkdpn7WZqQIDAQABo4IDszCCA68wPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIgvi9QYWBo0mBsYUEhJhygsKqDIFbht+nIoOavwACAWUC
# AQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMBsGCSsGAQQB
# gjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFJSfxen8Ka2WpHBOH5JgXGoC
# 47ZiMB8GA1UdIwQYMBaAFLb+NI5ijlm8ixD+aJ341TqQSgb1MIIBggYDVR0fBIIB
# eTCCAXUwggFxoIIBbaCCAWmGgcpsZGFwOi8vL0NOPVNvdXRoc2lkZSUyMEJhbmsl
# MjBJbnRlcm1lZGlhdGUlMjBDQSxDTj1jYSxDTj1DRFAsQ049UHVibGljJTIwS2V5
# JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zb3V0
# aHNpZGUsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
# amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hk1odHRwOi8vY2Euc291dGhz
# aWRlLmxvY2FsL0NlcnRFbnJvbGwvU291dGhzaWRlJTIwQmFuayUyMEludGVybWVk
# aWF0ZSUyMENBLmNybIZLaHR0cDovL2NhLnNvdXRoc2lkZS5sb2NhbC9jZXJ0ZGF0
# YS9Tb3V0aHNpZGUlMjBCYW5rJTIwSW50ZXJtZWRpYXRlJTIwQ0EuY3JsMIHaBggr
# BgEFBQcBAQSBzTCByjCBxwYIKwYBBQUHMAKGgbpsZGFwOi8vL0NOPVNvdXRoc2lk
# ZSUyMEJhbmslMjBJbnRlcm1lZGlhdGUlMjBDQSxDTj1BSUEsQ049UHVibGljJTIw
# S2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1z
# b3V0aHNpZGUsREM9bG9jYWw/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNz
# PWNlcnRpZmljYXRpb25BdXRob3JpdHkwOAYDVR0RBDEwL6AtBgorBgEEAYI3FAID
# oB8MHW5hdGhhbi5hbmRlcnNvbkBzb3V0aHNpZGUuY29tME8GCSsGAQQBgjcZAgRC
# MECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0yMS0yMDg4Mzk1MzE0LTQ0ODQxNTI4
# MC0xNTMyMzEzMDU1LTM1NzcxMA0GCSqGSIb3DQEBCwUAA4ICAQBD+DGTl0H1f/5y
# XPjRrTL6J2fDd5E99RLW5kcLZ3ESH6+4/r3FA1dpDQlhn7XLOgywmruLvahXL2Xo
# u6qSLZOg/jI//fEuifu4I6OR5c17I6fb6ppTvxBKT1Qg+njsa/O48vZ2fjw6qSdf
# jBUBgxAQAUZKxjXcpyU5juKHzkX45HsLfcPN8XpHJ4x7QSKWYWy0P/biYM2mxAjJ
# q54OMKmPoQHYQX1IUaPMJuqIQRINxZvaL2FtTJAkZnX2/wpeqUWqeLuBEgl79s1Q
# bjRlwSGuDkjkexH5p70ZM7ttTyzd0qjghHJHkoYF/2sbAcsEwKvq1msTtmzbfBUi
# v6MTfU4rtdKLCFRZncu9qHC38mTxj48HiJBxo587lDaq5vqsp/ux3C4vL+sN40qE
# /0l86nKx6WN6n47u9dqJq/dAZxHggMoSs+0elJPAYClC7AkLCNbl9aMU6lkwzVRQ
# Hj3M8IdHX4AZ4ru/smE3jQGXMqDpV0iYKTyM37y30/O/bKkqC7UJxMKeLqxceLND
# 1Pkhb/VLnWIEvz0L1/DlMMWxpFk7dXe8KMVpiKdzfRcq60LMDQjVlSO6CDmrKcfh
# GbZafFNL05NGYeMS3/NAAR0AghgYcR8obSATVZs3hXWXyUV9KDmAHjw15ARApC4Q
# V5LhM4mHq6fJ2OvkXTrJ+5WGfzIJojGCBWIwggVeAgEBMHIwWzEVMBMGCgmSJomT
# 8ixkARkWBWxvY2FsMRkwFwYKCZImiZPyLGQBGRYJc291dGhzaWRlMScwJQYDVQQD
# Ex5Tb3V0aHNpZGUgQmFuayBJbnRlcm1lZGlhdGUgQ0ECE0wAALbVuiaYWQZAIpIA
# AAAAttUwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwIwYJKoZIhvcNAQkEMRYEFIJnLaSoflAPvededQlY4cp3Wov8MA0GCSqG
# SIb3DQEBAQUABIIBANf3BcQ/j+Cr/DANQhk+cxt8uLcBNmPrcWL/7xD3EMf582S4
# lU3FYGINomGqdT0bG3lKIn/QuEsMLAlblQU/U4PdoPT+mb+xj6MXmgzQPSfw7ACl
# 4RsGNKiCIGGKTDgLdmY6Ag1xR725L/2Xc36kIMa1C1c882Gf4oB0Qzor+xWEO0RZ
# f/aFEyIXbCzVJVWaOhTkifejXbZ/NV3OfXImxrHm7lBjmRrpkBseJThVOdgk1Aqx
# r+SI4uOnXMl0a8LWo8y52sd6EQJ226pR3Itz2kscGNx7A9/zcSyVI+9ybhkJGKdB
# ErnvAjjiW8YpODhmIZ2rZZYIcGrWXw3q0muGTQihggNLMIIDRwYJKoZIhvcNAQkG
# MYIDODCCAzQCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhA5
# TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMxMDE4MjA1MzU1WjA/BgkqhkiG
# 9w0BCQQxMgQw2RFM9cnxR8RXNj/GBW9piFiE7u70yZaKgSWMCnoW9QnrbNjFkrDG
# 5NcisFXqbUUfMA0GCSqGSIb3DQEBAQUABIICADI1iuFFXnKiL48qyOm3l5ze0iVe
# +XsUD4uj+Lph8pixkKQw6VKtNoiRON6zjAElTf4BQTqefMT1JGVvL9rWiYnQkLx5
# UQv/yLhMlL5ZcnwwZXEixhlhX6Ivzf7EuINy7z4zxBvpcUiJx2jcNNeL7MEMppqU
# l/U0x84RuEu7V0bGobHQj61/WnoyzZE1XFdRoCS7cmTeL6ped/cSCUIxN59IeBTH
# Mx5WaywT+1IiIYaqA5dfs2CaL4rCtv0OQIPp0zAJjKN89KZx2NBDqwljwgAyLelY
# SsfXemvy2qFVRKecX3azkVPUJMjavl5VfRNYy0vu2wMjlqf7/UqLDbkWuj39KWeQ
# APbLbdYcZwNl3jUOGahYE/o5qIFYrsUsD6o5yT3ZaIHy5i9TfhmsBbyrABxnOPjm
# H7lyjyEMmXOM5GZUoGCBp1PoqnJYaBD1DBNmpO8AQFDbImFMA/W9bzCcGGj0iKoM
# 1BI775lZAk4m5tr3X/DEkaUsdEL1fc5qesCs473hbDXk0bppTUcy2OmJMaRWAWMF
# 3o6uKBoz2N3knivIGhYmuHZq7umuSFJdURpuoCrxzHx4Ad54RqlB3g2bSMM/KqrV
# XMETkLfRUcbBTehs5B5A0E0h8AkG4jDmO91z37zADeu6Q4MPs03+dwccFGqramOO
# NtldpTOazCVu8wmP
# SIG # End signature block
