# Template
Example 1:
```PowerShell
$SFISession = New-SFISession -IpAddress 192.168.175.1
New-SFIVlan -SFISession $SFISession -SiteId $SiteId -Verbose
```