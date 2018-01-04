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