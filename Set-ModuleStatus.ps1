function Set-ModuleStatus { 
  [cmdletBinding(SupportsShouldProcess)]
  param	(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory, HelpMessage = 'No module name specified!')] 
    [string] $Name
  )
  if(-Not (Get-Module -Name "$name")) { 
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