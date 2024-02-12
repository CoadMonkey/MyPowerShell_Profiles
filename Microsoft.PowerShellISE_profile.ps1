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
Import-PSSession (New-PSSession -name N8Exch2 -ConfigurationName Microsoft.Exchange -Authentication Kerberos -ConnectionUri http://exch2.southside.local/PowerShell/) -AllowClobber
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

# SIG # Begin signature block
# MIIjDQYJKoZIhvcNAQcCoIIi/jCCIvoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQ5B3yy3AbuNU9Ing6uoViUqH
# ZyOggh0VMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0B
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
# dJ69SK6YMIIG9TCCBN2gAwIBAgIQOUwl4XygbSeoZeI72R0i1DANBgkqhkiG9w0B
# AQwFADB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAj
# BgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwHhcNMjMwNTAzMDAw
# MDAwWhcNMzQwODAyMjM1OTU5WjBqMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFu
# Y2hlc3RlcjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDDCNTZWN0
# aWdvIFJTQSBUaW1lIFN0YW1waW5nIFNpZ25lciAjNDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAKSTKFJLzyeHdqQpHJk4wOcO1NEc7GjLAWTkis13sHFl
# gryf/Iu7u5WY+yURjlqICWYRFFiyuiJb5vYy8V0twHqiDuDgVmTtoeWBIHIgZEFs
# x8MI+vN9Xe8hmsJ+1yzDuhGYHvzTIAhCs1+/f4hYMqsws9iMepZKGRNcrPznq+kc
# Fi6wsDiVSs+FUKtnAyWhuzjpD2+pWpqRKBM1uR/zPeEkyGuxmegN77tN5T2MVAOR
# 0Pwtz1UzOHoJHAfRIuBjhqe+/dKDcxIUm5pMCUa9NLzhS1B7cuBb/Rm7HzxqGXtu
# uy1EKr48TMysigSTxleGoHM2K4GX+hubfoiH2FJ5if5udzfXu1Cf+hglTxPyXnyp
# sSBaKaujQod34PRMAkjdWKVTpqOg7RmWZRUpxe0zMCXmloOBmvZgZpBYB4DNQnWs
# +7SR0MXdAUBqtqgQ7vaNereeda/TpUsYoQyfV7BeJUeRdM11EtGcb+ReDZvsdSbu
# /tP1ki9ShejaRFEqoswAyodmQ6MbAO+itZadYq0nC/IbSsnDlEI3iCCEqIeuw7oj
# cnv4VO/4ayewhfWnQ4XYKzl021p3AtGk+vXNnD3MH65R0Hts2B0tEUJTcXTC5TWq
# LVIS2SXP8NPQkUMS1zJ9mGzjd0HI/x8kVO9urcY+VXvxXIc6ZPFgSwVP77kv7AkT
# AgMBAAGjggGCMIIBfjAfBgNVHSMEGDAWgBQaofhhGSAPw0F3RSiO0TVfBhIEVTAd
# BgNVHQ4EFgQUAw8xyJEqk71j89FdTaQ0D9KVARgwDgYDVR0PAQH/BAQDAgbAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMwQTA1
# BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNv
# bS9DUFMwCAYGZ4EMAQQCMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2Vj
# dGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcB
# AQRoMGYwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGln
# b1JTQVRpbWVTdGFtcGluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAEybZVj64HnP7xXDMm3eM5Hr
# d1ji673LSjx13n6UbcMixwSV32VpYRMM9gye9YkgXsGHxwMkysel8Cbf+PgxZQ3g
# 621RV6aMhFIIRhwqwt7y2opF87739i7Efu347Wi/elZI6WHlmjl3vL66kWSIdf9d
# hRY0J9Ipy//tLdr/vpMM7G2iDczD8W69IZEaIwBSrZfUYngqhHmo1z2sIY9wwyR5
# OpfxDaOjW1PYqwC6WPs1gE9fKHFsGV7Cg3KQruDG2PKZ++q0kmV8B3w1RB2tWBhr
# YvvebMQKqWzTIUZw3C+NdUwjwkHQepY7w0vdzZImdHZcN6CaJJ5OX07Tjw/lE09Z
# RGVLQ2TPSPhnZ7lNv8wNsTow0KE9SK16ZeTs3+AB8LMqSjmswaT5qX010DJAoLEZ
# Khghssh9BXEaSyc2quCYHIN158d+S4RDzUP7kJd2KhKsQMFwW5kKQPqAbZRhe8hu
# uchnZyRcUI0BIN4H9wHU+C4RzZ2D5fjKJRxEPSflsIZHKgsbhHZ9e2hPjbf3E7Tt
# oC3ucw/ZELqdmSx813UfjxDElOZ+JOWVSoiMJ9aFZh35rmR2kehI/shVCu0pwx/e
# OKbAFPsyPfipg2I2yMO+AIccq/pKQhyJA9z1XHxw2V14Tu6fXiDmCWp8KwijSPUV
# /ARP380hHHrl9Y4a1LlAMIIHEjCCBPqgAwIBAgITLgAAAAMraOwmaUObAgAAAAAA
# AzANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDExZTb3V0aHNpZGUgQmFuayBSb290
# IENBMB4XDTI0MDIwMjE2MTk0MVoXDTMyMDIwMjE2Mjk0MVowWzEVMBMGCgmSJomT
# 8ixkARkWBWxvY2FsMRkwFwYKCZImiZPyLGQBGRYJc291dGhzaWRlMScwJQYDVQQD
# Ex5Tb3V0aHNpZGUgQmFuayBJbnRlcm1lZGlhdGUgQ0EwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCfnlgy7aRsWtRENBM4rDHXqZ/uhUZtf/mtWzI2NqTn
# m0KJJl8ao1apls/EW0M8Ah5FHoXpucFVjmIaAVM1cEZt0olZ+uWdQR4ksFgYoVkN
# PKWARE/p11PBFQCEADU7D7MMtmCNvLSfDa658CEuH4Bwt7Jg/rbAdqyN+ZqK8t7Z
# wJ+BqthEQx/xcGbP6N0SlQJ16hsLOajkzQCkPOs+g+E6iCQHV7h6xIqeK+G+azZ4
# kBzmKaQvj6tHROhwZqVlL72TQp6HRMPCD1eTvNPolEc+Ht3W6MDv7Wk92RUvYZL8
# 2LrmUNkG2Hy3VFgHb0K4381BlYaeUiNx56NGFBSzjnvHbVYYppUe6cILgosKSNkt
# L9H7cGAP6tfo8U6wY8J7agUisOEYbIFh3kMhyzsKewdnReD9pzTffEHoaMo6wlL4
# mvskg4iuX+Iea0CMmaSEkmnvYxlyt+dbJtr62RjsCZO72tHp1IpPrI5GBBNEC5eJ
# 548W2TToHMrx/9hi+86VflWTchkhfjEIZ7yiEgu4CjLPBdQB7MIkF8nrL99I5/J3
# VzZ6o5zMwknog31aFfxWOFGiz3H7dd0REknL/Z660AIMPxPoBXJoXtPxsTnRF7Xl
# 8BMkq/ljAtt3rsj5Y78SWNZZt2gshn5neY7ciNZkMp2cmMnu8vmOV6BLX9s83eJv
# XQIDAQABo4ICBzCCAgMwEAYJKwYBBAGCNxUBBAMCAQEwIwYJKwYBBAGCNxUCBBYE
# FD5/t9H4RQ2OS6L3le2+UTn1epjUMB0GA1UdDgQWBBS2/jSOYo5ZvIsQ/mid+NU6
# kEoG9TAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTpige2QMZCpG7bI/DmWI4oi3py6jCB
# lgYDVR0fBIGOMIGLMIGIoIGFoIGChjtmaWxlOi8vLy9ST09UQ0EvQ2VydEVucm9s
# bC9Tb3V0aHNpZGUlMjBCYW5rJTIwUm9vdCUyMENBLmNybIZDaHR0cDovL2NhLnNv
# dXRoc2lkZS5sb2NhbC9jZXJ0ZGF0YS9Tb3V0aHNpZGUlMjBCYW5rJTIwUm9vdCUy
# MENBLmNybDCBtwYIKwYBBQUHAQEEgaowgacwTgYIKwYBBQUHMAKGQmZpbGU6Ly8v
# L1JPT1RDQS9DZXJ0RW5yb2xsL1JPT1RDQV9Tb3V0aHNpZGUlMjBCYW5rJTIwUm9v
# dCUyMENBLmNydDBVBggrBgEFBQcwAoZJaHR0cDovL2NhLnNvdXRoc2lkZS5sb2Nh
# bC9jZXJ0ZGF0YS9ST09UQ0FTb3V0aHNpZGUlMjBCYW5rJTIwUm9vdCUyMENBLmNy
# dDANBgkqhkiG9w0BAQsFAAOCAgEARB//ZToS8od2QLalr+VF4UcFf6z0MbOqIYpK
# odqj0JIkDWuAwgIzk87/dDOHvAhJhA7evrzrsxmqT25bEmr0Np3yB8Idw6dtBV/u
# d3p+d2W+tbJbgEWvSMjZ2X80U/QzisDgaXqd/QjzC6MRIDI3t0BfRPhX47AKNYHx
# zTFL8CfKrB/NpTZvkRdaGma3hCFBW1JFQRNxXRx25xBfW7ID8+zPTq3eXklMuuqN
# XI1jTeydmKPaHEJtJFGhjT/2loIXnB7h/mn6oUHGrW8tTp4eIuJHCZd6ie8nFOOl
# 37L8mDI1g29hrFKtlB0L6uLgUJ9OPhHukBCSjGd1X86Xdng5528dfYn6wLxscbAb
# Ai2GL0Y8LdE8xCiMInPH9hp2iI6wx1fj/ZrwyrI3L+m2t3H9kKKMY/QT95PBJ3mN
# obN7oz/5dFfF3CFFSodlumIOapS8G87WH9Rx1RuFN2OTGHbOKI3BOfICTpE4w3NE
# 2uR7kWAvn7Avk9dDsVoPOqaaK1CC7aU+Wj8OwvjuVmT+2dbPyQ8swDT+YckA2wNN
# 4v1lbazNc/93WmYUQ7JW5ALel0/3dfJ83DRvXqwRyl5iLD3YRLzRkZxlJq/zrJ1K
# kJLM6J6CHYnv9/TwP8G+Tvd0Nm3OzXUWSdjXIU3oeJrU5IkF93ZpPRmy5OwqVI9j
# HzB/6PIwgggSMIIF+qADAgECAhNMAAC21bommFkGQCKSAAAAALbVMA0GCSqGSIb3
# DQEBCwUAMFsxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEZMBcGCgmSJomT8ixkARkW
# CXNvdXRoc2lkZTEnMCUGA1UEAxMeU291dGhzaWRlIEJhbmsgSW50ZXJtZWRpYXRl
# IENBMB4XDTIzMDcwNjE1MTMxMloXDTI1MDMwMjE2NTY1NFowdTEVMBMGCgmSJomT
# 8ixkARkWBWxvY2FsMRkwFwYKCZImiZPyLGQBGRYJc291dGhzaWRlMRcwFQYDVQQL
# DA5CcmFuY2hlc19Vc2VyczEXMBUGA1UECwwOX0NvbXB1dGVyIERlcHQxDzANBgNV
# BAMTBkFOREVSTjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN1EgYP5
# SYIm/PBffDkC2lFB3//7ZZrNCV2xYvUA13P/bRmYs3ihBt2fSGMLVQl8HVLHKaWp
# zyytVwBteG89qeKIiVnp4n9+Qh0KcCXsfuYtdkOkFO/kETA5t6PXSQnbJpWVPK0N
# wGObnATPTONMM+WCgkDGhPgwLqzrWHLqcDCf2ft32XVkmfS4mx4VnlKsK7teGdX2
# x4tJy7Hp+agDRgzLUV/0DXRtKiWAP2ksTIfpXujZjDzYDaOe4QDroQw2aCedMYC8
# FRSNK00Xyi0WdDwfYjy9wTa3tGcCjW6JSBlf4H3If81CsIbWfKoli75Rwz1GC+pB
# 7/SUl4JHaZ+1makCAwEAAaOCA7MwggOvMD0GCSsGAQQBgjcVBwQwMC4GJisGAQQB
# gjcVCIL4vUGFgaNJgbGFBISYcoLCqgyBW4bfpyKDmr8AAgFlAgEAMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoG
# CCsGAQUFBwMDMB0GA1UdDgQWBBSUn8Xp/CmtlqRwTh+SYFxqAuO2YjAfBgNVHSME
# GDAWgBS2/jSOYo5ZvIsQ/mid+NU6kEoG9TCCAYIGA1UdHwSCAXkwggF1MIIBcaCC
# AW2gggFphoHKbGRhcDovLy9DTj1Tb3V0aHNpZGUlMjBCYW5rJTIwSW50ZXJtZWRp
# YXRlJTIwQ0EsQ049Y2EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
# LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c291dGhzaWRlLERDPWxv
# Y2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1j
# UkxEaXN0cmlidXRpb25Qb2ludIZNaHR0cDovL2NhLnNvdXRoc2lkZS5sb2NhbC9D
# ZXJ0RW5yb2xsL1NvdXRoc2lkZSUyMEJhbmslMjBJbnRlcm1lZGlhdGUlMjBDQS5j
# cmyGS2h0dHA6Ly9jYS5zb3V0aHNpZGUubG9jYWwvY2VydGRhdGEvU291dGhzaWRl
# JTIwQmFuayUyMEludGVybWVkaWF0ZSUyMENBLmNybDCB2gYIKwYBBQUHAQEEgc0w
# gcowgccGCCsGAQUFBzAChoG6bGRhcDovLy9DTj1Tb3V0aHNpZGUlMjBCYW5rJTIw
# SW50ZXJtZWRpYXRlJTIwQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c291dGhzaWRlLERD
# PWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0
# aW9uQXV0aG9yaXR5MDgGA1UdEQQxMC+gLQYKKwYBBAGCNxQCA6AfDB1uYXRoYW4u
# YW5kZXJzb25Ac291dGhzaWRlLmNvbTBPBgkrBgEEAYI3GQIEQjBAoD4GCisGAQQB
# gjcZAgGgMAQuUy0xLTUtMjEtMjA4ODM5NTMxNC00NDg0MTUyODAtMTUzMjMxMzA1
# NS0zNTc3MTANBgkqhkiG9w0BAQsFAAOCAgEAQ/gxk5dB9X/+clz40a0y+idnw3eR
# PfUS1uZHC2dxEh+vuP69xQNXaQ0JYZ+1yzoMsJq7i72oVy9l6Luqki2ToP4yP/3x
# Lon7uCOjkeXNeyOn2+qaU78QSk9UIPp47GvzuPL2dn48OqknX4wVAYMQEAFGSsY1
# 3KclOY7ih85F+OR7C33DzfF6RyeMe0EilmFstD/24mDNpsQIyaueDjCpj6EB2EF9
# SFGjzCbqiEESDcWb2i9hbUyQJGZ19v8KXqlFqni7gRIJe/bNUG40ZcEhrg5I5HsR
# +ae9GTO7bU8s3dKo4IRyR5KGBf9rGwHLBMCr6tZrE7Zs23wVIr+jE31OK7XSiwhU
# WZ3Lvahwt/Jk8Y+PB4iQcaOfO5Q2qub6rKf7sdwuLy/rDeNKhP9JfOpyseljep+O
# 7vXaiav3QGcR4IDKErPtHpSTwGApQuwJCwjW5fWjFOpZMM1UUB49zPCHR1+AGeK7
# v7JhN40BlzKg6VdImCk8jN+8t9Pzv2ypKgu1CcTCni6sXHizQ9T5IW/1S51iBL89
# C9fw5TDFsaRZO3V3vCjFaYinc30XKutCzA0I1ZUjugg5qynH4Rm2WnxTS9OTRmHj
# Et/zQAEdAIIYGHEfKG0gE1WbN4V1l8lFfSg5gB48NeQEQKQuEFeS4TOJh6unydjr
# 5F06yfuVhn8yCaIxggViMIIFXgIBATByMFsxFTATBgoJkiaJk/IsZAEZFgVsb2Nh
# bDEZMBcGCgmSJomT8ixkARkWCXNvdXRoc2lkZTEnMCUGA1UEAxMeU291dGhzaWRl
# IEJhbmsgSW50ZXJtZWRpYXRlIENBAhNMAAC21bommFkGQCKSAAAAALbVMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBTwyTwcO/YhFDs40VS08OaMePUXHDANBgkqhkiG9w0BAQEFAASC
# AQBIwbdT4xe2kTMdIcsJPFLNwrAlewHZxWLUu7GuuQYmzsG2Zk+MUVwNrq7F+mmu
# F7bCSrwn3COzRUdYmnLe/ZIIPaQ/4k/hKY1lf2nPWHGQR5UGRK8ANiM22zEP7a5D
# +4uhDCLzTREm4yNugJyGZqUlM3a07iucPGC2+Z72RXY3+ZVP1b/pRyF5JS9bDC0R
# SXGRroyRlpKuq9FufTvkTlbqpXKewzQFTYFJqvyNWjI+K81Zk8wTj+Rs7ueBl0bi
# +kIQhSvqy7UiAF+/5u04mzCyG9yAUsqgzzeul+LBpMsNpKbOIdOm2lhfSSY1PnM/
# oEXZbdg4qSH16/9rPowlEnktoYIDSzCCA0cGCSqGSIb3DQEJBjGCAzgwggM0AgEB
# MIGRMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIx
# EDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMG
# A1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIQOUwl4XygbSeoZeI7
# 2R0i1DANBglghkgBZQMEAgIFAKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTI0MDIxMjE2NDQ0OFowPwYJKoZIhvcNAQkEMTIEMJGc
# dzFd6r3s5KUhNh8uAkxP7Lrupt4UMPeES65EApSQQnOl+j8D86W2y/eWzb769DAN
# BgkqhkiG9w0BAQEFAASCAgBx5lymJuJRkAinmtn7CyYkyuJehDY1GycvQP4+8G01
# Z7VPON9wwVTEADU5sBTfGjYaukGbb/zvWwyuJlJl4AF0+MJKEOEoIzNwMrCjeqhf
# JFW+xxurGkh3WlyR/j4ohevoox+5JGqBUM7dyx7XmIJNpy+Uuy2llQ05cdxzfVbp
# 4ZEg2vsz2/do13BUxL8rinvClLtIO9gO6HvBoipjqZ9QlMWk7bbDhQ3CD1xUqenK
# rV7HwpLYbQWvRZdKa1ZjxmI0HXMEz9Hax05nvqo02mM+rc31U7M8sMH3sHP4Nc2h
# Y6kogA7Of46spaa3XttUygFtpYQMTZsNIkjp8F6HmFTmpVyCFAB8pTxI9WpwZ1nl
# cP99tyZaDona//3cM4IqHw96p26lrYRYAG//8PETm9/3XjHGG6c71QO4z5N8XP/J
# 1vTe9jny7UnrN77btycdW6zSbBdvqmmtCF80SMuxY+Bk+pZQ655kZ+hDSwig1Haz
# s7HHfaKz7sONhk1RtOUDXJc4hmWL9zzpnSciijxDvhc9WV62yKgUWHUamZIgcroH
# Yf5LOkYn5BZrsAOWl/WFLp4IU4us2ZgrRqgyq88as9ZhboGJVRjvFpuiTAdBDsE5
# wU64zDZlhjRYEDfJ0qcCsin0bxvm6BRG7A8Hq4b02xEyp7ky/hczHF4SjtwQUeNm
# ag==
# SIG # End signature block
