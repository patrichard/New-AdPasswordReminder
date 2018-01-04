function Remove-ScriptVariables {  
  [cmdletBinding(SupportsShouldProcess)]
  param(
    [string]$path
  )
  $result = Get-Content -Path $path |  
  ForEach-Object { 
    if ( $_ -match '(\$.*?)\s*=') {      
      $matches[1]  | Where-Object { $_ -notlike '*.*' -and $_ -notmatch 'result' -and $_ -notmatch 'env:'}  
    }  
  }  
  ForEach ($v in ($result | Sort-Object | Get-Unique)){		
    Remove-Variable -Name ($v.replace('$','')) -ErrorAction SilentlyContinue
  }
} # end function Remove-ScriptVariables