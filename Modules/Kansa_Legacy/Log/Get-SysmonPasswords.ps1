<#
.SYNOPSIS
    Get-SysmonPassword.ps1 extracts all Sysmon Events and looks for common commandline arguments that may contain a username and password
    Authored by Ruprecht
.DESCRIPTION
    Query the event log and pull back all Sysmon events searching for common commandline arguments that may contain passwords. Configured for Sysmon 10
.EXAMPLE
    .\Get-SysmonNetwork.ps1
    HostName    : Computername
    EventType   : Process Create
    EventID     : 1
    DateUTC     : 2019-10-18T17:54:00
    ProcessGuid : 1f25aada-fc38-5da9-0000-00108bcf201f
    ProcessId   : 176016
    Image       : C:\Windows\System32\net1.exe
    CommandLine : C:\windows\system32\net1 user /add user password
    SourceUser  : user1
    .LINK
    .NOTES
    Configured for Sysmon 10
    Sysmon configuration plays a large part in the amount of events.
    For offline parsing of event logs modify script to remove "-LogName" and add "-Path <PATH_to_Logs>". 
    e.g RawEvents = Get-WinEvent -Path c:\case\sysmon.evtx |  Where {$_.Message -Match 'schtasks.exe.*\/p' -or $_.Message -match 'net.*\/add' -or $_.Message -match 'wmic.*\/password' -or $_.Message -match 'taskkill.*\/P'  -or $_.Message -match 'tasklist.*\/P'}
#>
$RawEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where {$_.Message -Match 'schtasks.exe.*\/p' -or $_.Message -match 'net.*\/add' -or $_.Message -match 'wmic.*\/password' -or $_.Message -match 'taskkill.*\/P'  -or $_.Message -match 'tasklist.*\/P'}
$RawEvents | ForEach-Object {  
    $PropertyBag = @{
        HostName = $_.MachineName
        EventType = $_.Message.Split(":")[0]
        EventID = $_.Id
        DateUTC = Get-Date ($_.Properties[0].Value) -format s
        ProcessGuid = $_.Properties[1].Value
        ProcessId = $_.Properties[2].Value
        Image = $_.Properties[3].Value
        ParentImage = $_.Properties[15].Value
        CommandLine = $_.Properties[4].Value
        SourceUser = $_.Properties[6].Value
    }
    $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
    $Output | Select-Object HostName, EventType, EventID, DateUTC, ProcessGuid, ProcessId, Image, ParentImage, CommandLine, SourceUser
}
