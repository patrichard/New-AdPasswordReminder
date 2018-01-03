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
Write-Verbose -Message 'Defining functions'
function Set-ModuleStatus { 
  [cmdletBinding(SupportsShouldProcess)]
  param	(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'No module name specified!')] 
    [string] $Name
  )
  if(!(Get-Module -Name "$name")) { 
    if(Get-Module -ListAvailable | Where-Object {$_.name -eq "$name"}) { 
      Import-Module -Name "$name" 
      # module was imported
      return $true
    } else {
      # module was not available (Windows feature isn't installed)
      return $false
    }
  }else {
    # module was already imported
    return $true
  }
} # end function Set-ModuleStatus

function Remove-ScriptVariables {  
  [cmdletBinding(SupportsShouldProcess)]
  param(
    [string]$path
  )
  $result = Get-Content -Path $path |  
  ForEach { 
    if ( $_ -match '(\$.*?)\s*=') {      
      $matches[1]  | Where-Object { $_ -notlike '*.*' -and $_ -notmatch 'result' -and $_ -notmatch 'env:'}  
    }  
  }  
  ForEach ($v in ($result | Sort-Object | Get-Unique)){		
    Remove-Variable -Name ($v.replace('$','')) -ErrorAction SilentlyContinue
  }
} # end function Remove-ScriptVariables

function Invoke-Installation	{
  [cmdletBinding(SupportsShouldProcess, HelpUri = 'http://technet.microsoft.com/en-us/library/cc725744(WS.10).aspx')]
  param()
  $error.clear()
  Write-Output -InputObject "Creating scheduled task `"$ScriptName`"..."
  $TaskCreds = Get-Credential -Credential ("$env:userdnsdomain\$env:username")
  $TaskPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($TaskCreds.Password))
  schtasks /create /tn $ScriptName /tr "$env:windir\system32\windowspowershell\v1.0\powershell.exe -noprofile -command $ScriptPathAndName" /sc Daily /st 06:00 /ru $TaskCreds.UserName /rp $TaskPassword | Out-Null
  if (-Not ($error)){
    Write-Host 'Installation complete!' -ForegroundColor green
  }else{
    Write-Host 'Installation failed!' -ForegroundColor red
  }
  Remove-Variable -Name taskpassword
  exit
} # end function Invoke-Installation

function Get-ADUserPasswordExpirationDate {
  [cmdletBinding(SupportsShouldProcess)]
  Param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, HelpMessage = 'Identity of the Account')]
    [Object]$accountIdentity
  )
  PROCESS {
    Write-Verbose -Message "Getting the user info for $accountIdentity"
    $accountObj = Get-ADUser $accountIdentity -properties PasswordExpired, PasswordNeverExpires, PasswordLastSet, name, mail
    # Make sure the password is not expired, and the account is not set to never expire
    Write-Verbose -Message 'verifying that the password is not expired, and the user is not set to PasswordNeverExpires'
    if (((!($accountObj.PasswordExpired)) -and (!($accountObj.PasswordNeverExpires))) -or ($PreviewUser)) {
      Write-Verbose -Message 'Verifying if the date the password was last set is available'
      $passwordSetDate = $accountObj.PasswordLastSet     	
      if ($passwordSetDate -ne $null) {
        $maxPasswordAgeTimeSpan = $null
        # see if we're at Windows2008 domain functional level, which supports granular password policies
        Write-Verbose -Message 'Determining domain functional level'
        if ($global:dfl -ge 4) { # 2008 Domain functional level
          $accountFGPP = Get-ADUserResultantPasswordPolicy $accountObj
          if ($accountFGPP -ne $null) {
            $maxPasswordAgeTimeSpan = $accountFGPP.MaxPasswordAge
          } else {
            $maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
          }
        } else { # 2003 or ealier Domain Functional Level
          $maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
        }				
        if ($maxPasswordAgeTimeSpan -eq $null -or $maxPasswordAgeTimeSpan.TotalMilliseconds -ne 0) {
          $DaysTillExpire = [math]::round(((New-TimeSpan -Start (Get-Date) -End ($passwordSetDate + $maxPasswordAgeTimeSpan)).TotalDays),0)
          if ($preview){$DaysTillExpire = 1}
          if ($DaysTillExpire -le $DaysToWarn){
            Write-Verbose -Message 'User should receive email'
            $PolicyDays = [math]::round((($maxPasswordAgeTimeSpan).TotalDays),0)
            if ($demo)	{Write-Host ('{0,-25}{1,-8}{2,-12}' -f $accountObj.Name, $DaysTillExpire, $PolicyDays)}
            # start assembling email to user here
            $EmailName = $accountObj.Name						
            $DateofExpiration = (Get-Date).AddDays($DaysTillExpire)
            $DateofExpiration = (Get-Date -Date ($DateofExpiration) -Format $DateFormat)						

            Write-Verbose -Message 'Assembling email message'
            [string]$emailbody = @"
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>body,p {font-size: 11.0pt; font-family: "Calibri","sans-serif";}</style>
	</head>
<body>	
"@

            if (!($NoImages)){
              $emailbody += @"	
	<table id="email" border="0" cellspacing="0" cellpadding="0" width="655" align="center">
		<tr>
			<td align="left" valign="top"><img src="$ImagePath/spacer.gif" alt="Description: $ImagePath/spacer.gif" width="46" height="28" align="absMiddle">
			</td>
		</tr>
"@

              if ($HelpDeskURL){
                $emailbody += @"
			<tr><td height="121" align="left" valign="bottom"><a href="$HelpDeskURL"><img src="$ImagePath/header.gif" border="0" alt="Description: $ImagePath/header.gif" width="655" height="121"></a></td></tr>
"@
              }else{
                $emailbody += @"	
			<tr><td height="121" align="left" valign="bottom"><img src="$ImagePath/header.gif" border="0" alt="Description: $ImagePath/header.gif" width="655" height="121"></td></tr>
"@
              }

              $emailbody += @"
		<tr>
			<td>
				<table id="body" border="0" cellspacing="0" cellpadding="0">
					<tr>
						<td width="1" align="left" valign="top" bgcolor="#a8a9ad"><img src="$ImagePath/spacer50.gif" alt="Description: $ImagePath/spacer50.gif" width="1" height="50"></td>
						<td><img src="$ImagePath/spacer.gif" alt="Description: $ImagePath/spacer.gif" width="46" height="106"></td>
						<td id="text" width="572" align="left" valign="top" style="font-size: 12px; color: #000000; line-height: 17px; font-family: Verdana, Arial, Helvetica, sans-serif">
"@
            }
            if ($DaysTillExpire -le 1){
              $emailbody += @"
		<div align='center'>
			<table border='0' cellspacing='0' cellpadding='0' style='width: 510px; background-color: white; border: 0px;'>
				<tr>
"@
              if (!($NoImages)){
                $emailbody += @"
					<td align='right'><img width='36' height='28' src='$ImagePath/image001b.gif' alt='Description: $ImagePath/image001b.gif'></td>	
"@
              }
              $emailbody += @"
					<td style="font-family: verdana; background: #E12C10; text-align: center; padding: 0px; font-size: 9.0pt; color: white">ALERT: You must change your password today or you will be locked out!</td>		
"@
              if (!($NoImages)){
                $emailbody += @"
					<td align='left'><img border='0' width='14' height='28' src='$ImagePath/image005b.gif' alt='Description: $ImagePath/image005b.gif'></td>
"@
              }
              $emailbody += @"
				</tr>
			</table>
		</div>
"@
            }

            $emailbody += @"
			<p style="font-weight: bold">Hello, $EmailName,</p>
			<p>It's change time again! Your $company password expires in <span style="background-color: red; color: white; font-weight: bold;">&nbsp;$DaysTillExpire&nbsp;</span> day(s), on $DateofExpiration.</p>
			<p>Please use one of the methods below to update your password:</p>
			<ol>
				<li>$company office computers and Terminal Server users: You may update your password on your computer by pressing Ctrl-Alt-Delete and selecting 'Change Password' from the available options. If you use a $company laptop in addition to a desktop PC, be sure and read #3 below.</li>
				<li>Remote Outlook Client, Mac, and/or Outlook Web App users: If you only access our email system, please use the following method to easily change your password:</li>
				<ul>
					<li>Log into <a href="$owaurl">Outlook Web App</a> using Internet Explorer (PC) or Safari or Firefox (Mac).</li>
					<li>Click on the Options button in the upper right corner of the page.</li>		
					<li>Select the &quot;Change Password&quot; link to change your password.</li>
					<li>Enter your current password, then your new password twice, and click Save</li>
					<li><span style="font-weight: bold">NOTE:</span> You will now need to use your new password when logging into Outlook Web App, Outlook 2010, SharePoint, Windows Mobile (ActiveSync) devices, etc. Blackberry Enterprise Users (BES) will not need to update their password. Blackberry Internet Service (BIS) users will be required to use their new password on their device.</li>
				</ul>
				<li>$company issued laptops: If you have been issued a $company laptop, you must be in a corporate office and directly connected to the company network to change your password. If you also use a desktop PC in the office, you must remember to always update your domain password on the laptop first. Your desktop will automatically use the new password.</li>
				<ul>
					<li>Log in on laptop</li>
					<li>Press Ctrl-Alt-Delete and select 'Change Password' from the available options.</li>
					<li>Make sure your workstation (if you have one) has been logged off any previous sessions so as to not cause conflict with your new password.</li>
				</ul>
			</ol>
			<p>Think you've got a complex password? Run it through the <a href="http://www.passwordmeter.com/">The Password Meter</a></p>
			<p>Think your password couldn't easily be hacked? See how long it would take: <a href="http://howsecureismypassword.net/">How Secure Is My Password</a></p>
			<p>Remember, if you do not change your password before it expires on $DateofExpiration, you will be locked out of all $company Computer Systems until an Administrator unlocks your account.</p>
			<p>If you are traveling or will not be able to bring your laptop into the office before your password expires, please call the number below for additional instructions.</p>
			<p>You will continue to receive these emails daily until the password is changed or expires.</p>

			<p>Thank you,<br />
			The $company Help Desk<br />
			$HelpDeskPhone</p>
"@			
            if ($accountFGPP -eq $null){ 
              $emailbody += @"
			<table style="background-color: #dedede; border: 1px solid black">
				<tr>
					<td style="font-size: 12px; color: #000000; line-height: 17px; font-family: Verdana, Arial, Helvetica, sans-serif"><b>$company Password Policy</b>
						<ul>
							<li>Your password must have a minimum of a $MinPasswordLength characters.</li>
							<li>You may not use a previous password.</li>
							<li>Your password must not contain parts of your first, last, or logon name.</li>
							<li>Your password must be changed every $PolicyDays days.</li>
"@							

              if ($PasswordComplexity){
                Write-Verbose -Message 'Password complexity'
                $emailbody += @"
							<li>Your password requires a minimum of two of the following three categories:</li>
							<ul>
								<li>1 upper case character (A-Z)</li>
								<li>1 lower case character (a-z)</li>
								<li>1 numeric character (0-9)</li>								
							</ul>
"@
              }
              $emailbody += @"
							<li>You may not reuse any of your last $PasswordHistory passwords</li>
						</ul>
					</td>
				</tr>
			</table>
"@
            }
            if (!($NoImages)){
              $emailbody += @"
							</td>
							<td width="49" align="left" valign="top"><img src="$ImagePath/spacer50.gif" alt="" width="49" height="50"></td>
							<td width="1" align="left" valign="top" bgcolor="#a8a9ad"><img src="$ImagePath/spacer50.gif" alt="Description: $ImagePath/spacer50.gif" width="1" height="50"></td>
						</tr>
					</table>
					<table id="footer" border="0" cellspacing="0" cellpadding="0" width="655">
						<tr>
							<td><img src="$ImagePath/footer.gif" alt="Description: $ImagePath/footer.gif" width="655" height="81"></td>
						</tr>
					</table>
					<table border="0" cellspacing="0" cellpadding="0" width="655" align="center">
						<tr>
							<td align="left" valign="top"><img src="$ImagePath/spacer.gif" alt="Description: $ImagePath/spacer.gif" width="36" height="1"></td>
							<td align="middle" valign="top"><font face="Verdana" size="1" color="#000000"><p>This email was sent by an automated process. 
"@
            }
            if ($HelpDeskURL){
              $emailbody += @"
							If you would like to comment on it, please visit <a href="$HelpDeskURL"><font color="#ff0000"><u>click here</u></font></a>
"@
            }
            if (!($NoImages)){
              $emailbody += @"
								</p></font>
							</td>
							<td align="left" valign="top"><img src="$ImagePath/spacer.gif" alt="Description: $ImagePath/spacer.gif" width="36" height="1"></td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
"@
            }
            $emailbody += @"
	</body>
</html>
"@
            if (!($demo)){
              $emailto = $accountObj.mail
              if ($emailto){
                Write-Verbose -Message "Sending demo message to $emailto"
                Send-MailMessage -To $emailto -Subject "Your password expires in $DaysTillExpire day(s)" -Body $emailbody -From $EmailFrom -Priority High -BodyAsHtml
                $global:UsersNotified++
              }else{
                Write-Verbose -Message 'Can not email this user. Email address is blank'
              }
            }
          }
        }
      }
    }
  }
} # end function Get-ADUserPasswordExpirationDate
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
  Set-ModuleStatus -name ServerManager
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
$EventLogText = "Finished processing $global:UsersNotified account(s). `n`nFor more information about this script, run Get-Help .\$ScriptName. See the blog post at http://www.ucunleashed.com/318."
$evt.WriteEntry($EventLogText,$infoevent,70)

# $WhatIfPreference = $false

Remove-ScriptVariables -path $ScriptPathAndName