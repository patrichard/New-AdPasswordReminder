<# 
    .SYNOPSIS
    Notifies users that their password is about to expire.

    .DESCRIPTION
    Let's users know their password will soon expire. Details the steps needed to change their password, and advises on what the password policy requires. Accounts for both standard Default Domain Policy based password policy and the fine grain password policy available in 2008 domains.

    .NOTES
    Version    	      	: v3.0 - See changelog at https://ucunleashed.com/596
    Wish list						: Set $DaysToWarn automatically based on Default Domain GPO setting
                        : Description for scheduled task
                        : Verify it's running on R2, as apparently only R2 has the AD commands?
                        : Determine password policy settings for FGPP users
                        : better logging
    Rights Required			: local admin on server it's running on
    Sched Task Req'd		: Yes - install mode will automatically create scheduled task
    Lync Version				: N/A
    Exchange Version		: 2007 or later
    Author       				: M. Ali (original AD query), Pat Richard, Lync MVP
    Email/Blog/Twitter	: pat@innervation.com 	https://ucunleashed.com @patrichard
    Dedicated Post			: https://ucunleashed.com/318
    Disclaimer   				: You running this script means you won't blame me if this breaks your stuff.
    Acknowledgements 		: (original) http://blogs.msdn.com/b/adpowershell/archive/2010/02/26/find-out-when-your-password-expires.aspx
                        : (date) http://technet.microsoft.com/en-us/library/ff730960.aspx
                        :	(calculating time) http://blogs.msdn.com/b/powershell/archive/2007/02/24/time-till-we-land.aspx
                        : http://social.technet.microsoft.com/Forums/en-US/winserverpowershell/thread/23fc5ffb-7cff-4c09-bf3e-2f94e2061f29/
                        : http://blogs.msdn.com/b/adpowershell/archive/2010/02/26/find-out-when-your-password-expires.aspx
                        : (password decryption) http://social.technet.microsoft.com/Forums/en-US/winserverpowershell/thread/f90bed75-475e-4f5f-94eb-60197efda6c6/
                        : (determine per user fine grained password settings) http://technet.microsoft.com/en-us/library/ee617255.aspx
    Assumptions					: ExecutionPolicy of AllSigned (recommended), RemoteSigned or Unrestricted (not recommended)
    Limitations					: 
    Known issues				: Doesn't get password complexity info for fine grained password policies (just default password policy for now)

    .LINK     
    https://ucunleashed.com/318

    .INPUTS
    None. You cannot pipe objects to this script
		
    .EXAMPLE 
    .\New-PasswordReminder.ps1
	
    Description
    -----------
    Searches Active Directory for users who have passwords expiring soon, and emails them a reminder with instructions on how to change their password.

    .EXAMPLE 
    .\New-PasswordReminder.ps1 -demo
	
    Description
    -----------
    Searches Active Directory for users who have passwords expiring soon, and lists those users on the screen, along with days till expiration and policy setting

    .EXAMPLE 
    .\New-PasswordReminder.ps1 -Preview -PreviewUser [username]
	
    Description
    -----------
    Sends the HTML formatted email of the user specified via -PreviewUser. This is used to see what the HTML email will look like to the users.

    .EXAMPLE 
    .\New-PasswordReminder.ps1 -install
	
    Description
    -----------
    Creates the scheduled task for the script to run everyday at 6am. It will prompt for the password for the currently logged on user. It does NOT create the required Exchange receive connector.

#> 
#Requires -Version 3.0 

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default', HelpUri = 'https://ucunleashed.com/318')]
param(
  # Runs the script in demo mode. No emails are sent to the user(s), and onscreen output includes those who are expiring soon.
  [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Demo')] 
  [switch] $Demo,

  # Create the scheduled task to run the script daily. It does NOT create the required Exchange receive connector.
  [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Install')] 
  [switch] $Install,

  # User name of user to send the preview email message to.
  [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Preview')] 
  [string] $PreviewUser,

  # When specified, sends the email with no images, but keeps all other HTML formatting.
  [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Default')]
  [Parameter(ParameterSetName = 'Preview')]
  [switch] $NoImages
)
Write-Verbose -Message 'Setting variables'
[string] $Company = 'Contoso Ltd'
[string] $OwaUrl = 'https://mail.contoso.com'
[string] $PSEmailServer = '10.9.0.11'
[string] $EmailFrom = 'Help Desk <helpdesk@contoso.com>'
# Set the following to blank to exclude it from the emails
[string] $HelpDeskPhone = '(586) 555-1010'
# Set the following to blank to remove the link from the emails
[string] $HelpDeskURL = 'https://intranet.contoso.com/'
[string] $TranscriptFilename = $MyInvocation.MyCommand.Name + ' ' + $env:ComputerName + ' {0:yyyy-MM-dd hh-mmtt}.log' -f (Get-Date)
[int] $global:UsersNotified = 0
[int] $DaysToWarn = 14
# Below path should be accessible by ALL users who may receive emails. This includes external/mobile users.
[string] $ImagePath = 'http://www.contoso.com/images/'
[string] $ScriptName = $MyInvocation.MyCommand.Name
[string] $ScriptPathAndName = $MyInvocation.MyCommand.Definition
[string] $ou
# Change the following to alter the format of the date in the emails sent
# See http://technet.microsoft.com/en-us/library/ee692801.aspx for more info
[string] $DateFormat = 'd'

if ($PreviewUser){
  $Preview = $true
}

#region functions
Write-Verbose -Message 'dot source functions'
#dot source functions
. $psscriptroot\functions\Set-ModuleStatus.ps1
. $psscriptroot\functions\Remove-ScriptVariables.ps1
. $psscriptroot\functions\Invoke-Installation.ps1
. $psscriptroot\functions\Get-AdUserPasswordExpirationDate.ps1
#endregion functions

if ($install){
  Write-Verbose -Message 'Install mode'
  Invoke-Installation
  Exit
}

Write-Verbose -Message 'Checking for ActiveDirectory module'
if ((Set-ModuleStatus -name ActiveDirectory) -eq $false){
  $error.clear()
  Write-Host 'Installing the Active Directory module...' -ForegroundColor yellow
  Set-ModuleStatus -Name ServerManager
  Add-WindowsFeature RSAT-AD-PowerShell
  if ($error){
    Write-Host 'Active Directory module could not be installed. Exiting...' -ForegroundColor red
    if ($transcript){Stop-Transcript}
    exit
  }
}
Write-Verbose -Message 'Getting Domain functional level'
$global:dfl = (Get-AdDomain).DomainMode
# Get-ADUser -filter * -properties PasswordLastSet,EmailAddress,GivenName -SearchBase "OU=Users,DC=domain,DC=test" |foreach {
if (!($PreviewUser)){
  if ($ou){
    Write-Verbose -Message "Filtering users to $ou"
    # $users = Get-AdUser -filter * -SearchScope subtree -SearchBase $ou -ResultSetSize $null
    $users = Get-AdUser -ldapfilter '(!(name=*$))' -SearchScope subtree -SearchBase $ou -ResultSetSize $null
  }else{
    # $users = Get-AdUser -filter * -ResultSetSize $null
    $users = Get-AdUser -ldapfilter '(!(name=*$))' -ResultSetSize $null
  }
}else{
  Write-Verbose -Message 'Preview mode'
  $users = Get-AdUser $PreviewUser
}
if ($demo){
  Write-Verbose -Message 'Demo mode'
  # $WhatIfPreference = $true
  Write-Output -InputObject "`n"
  Write-Host ('{0,-25}{1,-8}{2,-12}' -f 'User', 'Expires', 'Policy') -ForegroundColor cyan
  Write-Host ('{0,-25}{1,-8}{2,-12}' -f '========================', '=======', '===========') -ForegroundColor cyan
}

Write-Verbose -Message 'Setting event log configuration'
[object]$evt = New-Object -TypeName System.Diagnostics.EventLog -ArgumentList ('Application')
[string]$evt.Source = $ScriptName
$infoevent = [Diagnostics.EventLogEntryType]::Information
[string]$EventLogText = 'Beginning processing'
# $evt.WriteEntry($EventLogText,$infoevent,70)

Write-Verbose -Message 'Getting password policy configuration'
$DefaultDomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
[int]$MinPasswordLength = $DefaultDomainPasswordPolicy.MinPasswordLength
# this needs to look for FGPP, and then default to this if it doesn't exist
[bool]$PasswordComplexity = $DefaultDomainPasswordPolicy.ComplexityEnabled
[int]$PasswordHistory = $DefaultDomainPasswordPolicy.PasswordHistoryCount

ForEach ($user in $users){
  Get-ADUserPasswordExpirationDate $user.samaccountname
}

Write-Verbose -Message 'Writing summary event log entry'
$EventLogText = "Finished processing $global:UsersNotified account(s). `n`nFor more information about this script, run Get-Help .\$ScriptName. See the blog post at https://ucunleashed.com/318."
$evt.WriteEntry($EventLogText,$infoevent,70)

# $WhatIfPreference = $false

Remove-ScriptVariables -path $ScriptPathAndName
