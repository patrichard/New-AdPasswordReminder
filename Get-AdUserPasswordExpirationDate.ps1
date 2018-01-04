function Get-ADUserPasswordExpirationDate {
  [cmdletBinding(SupportsShouldProcess)]
  Param (
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, HelpMessage = 'Identity of the Account')]
    [Object]$accountIdentity
  )
  PROCESS {
    Write-Verbose -Message "Getting the user info for $accountIdentity"
    $accountObj = Get-ADUser -Identity $accountIdentity -Properties PasswordExpired, PasswordNeverExpires, PasswordLastSet, Name, Mail
    # Make sure the password is not expired, and the account is not set to never expire
    Write-Verbose -Message 'verifying that the password is not expired, and the user is not set to PasswordNeverExpires'
    if (((-Not ($accountObj.PasswordExpired)) -and (-Not ($accountObj.PasswordNeverExpires))) -or ($PreviewUser)) {
      Write-Verbose -Message 'Verifying if the date the password was last set is available'
      $passwordSetDate = $accountObj.PasswordLastSet     	
      if ($passwordSetDate -ne $null) {
        $maxPasswordAgeTimeSpan = $null
        # see if we're at Windows2008 domain functional level, which supports granular password policies
        Write-Verbose -Message 'Determining domain functional level'
        if ($global:dfl -ge 4) { # 2008 Domain functional level
          $accountFGPP = Get-ADUserResultantPasswordPolicy -Identity $accountObj
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
            [string]$emailbody = @'
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>body,p {font-size: 11.0pt; font-family: "Calibri","sans-serif";}</style>
	</head>
<body>	
'@

            if (-Not ($NoImages)){
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
              if (-Not ($NoImages)){
                $emailbody += @"
					<td align='right'><img width='36' height='28' src='$ImagePath/image001b.gif' alt='Description: $ImagePath/image001b.gif'></td>	
"@
              }
              $emailbody += @'
					<td style="font-family: verdana; background: #E12C10; text-align: center; padding: 0px; font-size: 9.0pt; color: white">ALERT: You must change your password today or you will be locked out!</td>		
'@
              if (-Not ($NoImages)){
                $emailbody += @"
					<td align='left'><img border='0' width='14' height='28' src='$ImagePath/image005b.gif' alt='Description: $ImagePath/image005b.gif'></td>
"@
              }
              $emailbody += @'
				</tr>
			</table>
		</div>
'@
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
                $emailbody += @'
							<li>Your password requires a minimum of two of the following three categories:</li>
							<ul>
								<li>1 upper case character (A-Z)</li>
								<li>1 lower case character (a-z)</li>
								<li>1 numeric character (0-9)</li>								
							</ul>
'@
              }
              $emailbody += @"
							<li>You may not reuse any of your last $PasswordHistory passwords</li>
						</ul>
					</td>
				</tr>
			</table>
"@
            }
            if (-Not ($NoImages)){
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
            if (-Not ($NoImages)){
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
            $emailbody += @'
	</body>
</html>
'@
            if (-Not ($demo)){
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