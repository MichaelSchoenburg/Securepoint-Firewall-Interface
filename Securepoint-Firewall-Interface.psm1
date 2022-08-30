# To import this Module: Import-Module .\Securepoint-Firewall-Interface.psd1

# TODO:
# More TODOs below (search for "# TODO").
# Add logging
# Check if local IP is on 192.168.175.0/24 network
# Add capability to load configuration files
# Add function to check if default settings are set/settings are correct (check if cloud backup active)

# Manual Tasks:
# Initial setup: assign license, name device, set date
# Activate cloud backup

function New-SFISession {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0
            )]
        [ipaddress]
        $IpAddress
    )

    # Source of inspiration: https://sid-500.com/2017/12/09/powershell-find-out-whether-a-host-is-really-down-or-not-with-test-connectionlocalsubnet-ping-arp/
    function Test-SFIConnection {
        param (
            [Parameter(
                Mandatory = $True,
                Position = 0
            )]
            [System.Net.IPAddress]
            $IpAddress
        )
        
        arp -d
        $ping = Test-Connection -ComputerName $IpAddress -Count 3 -Quiet
        $arp = [boolean](arp -a | Select-String "$IpAddress")

        If ($ping -and $arp){
            return @{
                ExitCode = 0
                Comment = 'Firewall is up.'
            }
        }
        elseif ($ping -and !$arp){
        return @{
                ExitCode = 2
                Comment = "Firewall is up, but possibly not on local subnet."
            }
        }
        elseif (!$ping -and $arp){
            return @{
                ExitCode = 3
                Comment = "Firewall not reachable. Possible Cause: Windows Firewall is blocking traffic."
            }
        }
        else{
            return @{
                ExitCode = 1
                Comment = "Firewall is down."
            }
        }
    }

    $Test = Test-SFIConnection -IpAddress $IpAddress
    if ($Test.ExitCode -ne 0) {
        throw "Can't connect to Securepoint firewall at $( $IpAddress ). Test result: $( $Test.Comment )" # Function will terminate
    } else {
        Write-Verbose "Firewall is reachable at $( $IpAddress )."
    }

    $cred = Get-Credential
    $session = New-SSHSession -ComputerName $IpAddress -Credential $cred -AcceptKey
    return $session
}

# TODO: This must not contain any defaults from ITCE, thus no default values should be set! There has to be a separate function for ITCE defaults!
function Set-SFISettings {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true
        )]
        [SshSession]
        $SFISession,

        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [ipaddress]
        $FirewallIpAddress = '192.168.175.1',

        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $LoadDefaults,

        [Parameter(
            Mandatory = $false
        )]
        [string]
        $GlobalContactPerson = 'IT-Center Engels',

        [Parameter(
            Mandatory = $false
        )]
        [string]
        $GlobalContactEMailAddress = 'support@itc-engels.de',

        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet('Deactivate','Log','LogAndDrop')]
        [string]
        $CyberDefenseCloud = 'LogAndDrop'
    )

    <#
    .SYNOPSIS
        Set-SFISettings
    .DESCRIPTION
        If you just call one of the functions without specifying any parameters, default parameters will be used. 
        Thus if you just call Set-SFISettings the default configuration will be rolled out.
    .SYNTAX
    .PARAMETERS
    .EXAMPLE
        PS C:\> Set-SFISettings
        Default configuration will be rolled out.
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Returns true or false depending on whether errors occurred or not.
    .RELATED LINKS
        GitHub: https://github.com/MichaelSchoenburg/Securepoint-Firewall-Interface
        Style guide: https://poshcode.gitbook.io/powershell-practice-and-style/
        Performance Considerations: https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/script-authoring-considerations?view=powershell-7.1
    .NOTES
        Script-Author: Michael Schönburg
        This projects code loosely follows the PowerShell Practice and Style guide, as well as Microsofts PowerShell scripting performance considerations (see related links).
    .REMARKS
        To see the examples, type: "get-help Get-HotFix -examples".
        For more information, type: "get-help Get-HotFix -detailed".
        For technical information, type: "get-help Get-HotFix -full".
        For online help, type: "get-help Get-HotFix -online"
    #>

    if ($LoadDefaults -or $PSBoundParameters.ContainsKey('GlobalContactPerson')) {
        # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > FIREWALL > Global contact person:
        Invoke-SSHCommand -SSHSession $SFISession -Command "extc global set variable `"GLOB_ADMIN_NAME`" value [ `"$GlobalContactPerson`" ]"
    }

    if ($LoadDefaults -or $PSBoundParameters.ContainsKey('GlobalContactEMailAddress')) {
        # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > FIREWALL > Global email address:
        Invoke-SSHCommand -SSHSession $SFISession -Command "extc global set variable `"GLOB_ADMIN_EMAIL`" value [ `"$GlobalContactEMailAddress`" ]"
    }

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > FIREWALL > Report language:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_LANGUAGE" value [ "DE" ]'

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > DNS SERVER > Check Nameserver prior to local cache:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_NAMESERVER_ASK_REMOTE_FIRST" value "1"'

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > DNS SERVER > Primary Nameserver >, Secondary Nameserver:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_NAMESERVER" value [ "8.8.8.8" "1.1.1.1" ]'

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > TIME SETTINGS > Timezone:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_TIMEZONE" value [ "Europe/Berlin" ]'

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > TIME SETTINGS > NTP Server:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_TIMEZONE" value [ "Europe/Berlin" ]'

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > WEBSERVER
    # Coming soon

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > ADVANCED SETTINGS > Maximum Active Connections:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "securepoint_firewall" variable "IPCONNTRACK" value [ "0" ]'

    # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > ADVANCED SETTINGS > Last Rule Logging:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "securepoint_firewall" variable "LASTRULE_LOGGING" value [ "1" ]'

    # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > IP Address:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_HTTP_PARENT_PROXY_ADDR" value [ "" ]'

    # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > Port:
    # Coming soon

    # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > User:
    # Coming soon

    # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > Password:
    # Coming soon

    # NETWORK > APPLIANCE SETTINGS > ADMINISTRATION:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "spresolverd" variable [ "MANAGER_HOST_LIST" ] value [ "centervision.spdns.de" ]'

    # NETWORK > APPLIANCE SETTINGS > SYSLOG > Log the UTM hostname in the syslog messages:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "syslog" variable "WRITE_HOST" value [ "0" ]'

    # NETWORK > APPLIANCE SETTINGS > SNMP > SNMP Version:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "snmpd" variable "ENABLE_SNMP_V1" value [ "0" ]'

    # NETWORK > APPLIANCE SETTINGS > SNMP > SNMP Version:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "snmpd" variable "ENABLE_SNMP_V2" value [ "0" ]'

    # NETWORK > APPLIANCE SETTINGS > SNMP > SNMP Version:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "snmpd" variable "ENABLE_SNMP_V3" value [ "0" ]'

    # NETWORK > QOS > NETWORK INTERFACES > GENERAL > Mode:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_QOS_MODE" value [ "auto" ]'
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc global set variable "GLOB_QOS_INTERFACE" value [ "" ]'

    # Applications > HTTP PROXY > GENERAL > Proxy Port:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "PROXY_PORT" value [ "8080" ]'

    # Applications > HTTP PROXY > GENERAL > Outgoing Address:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "OUTGOING_ADDR" value [ "" ]'

    # Applications > HTTP PROXY > GENERAL > Forward requests to system-wide parent proxy:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_FORWARD" value "0"'

    # Applications > HTTP PROXY > GENERAL > Authentication method:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_AUTH_LOCAL" value "0"'
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_AUTH_RADIUS" value "0"'
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_AUTH_NTLM" value "0"'
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_AUTH_NTLM" value "0"'

    # Applications > HTTP PROXY > GENERAL > Allow access only from local sources:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "RESTRICT_CLIENT_ACCESS" value [ "1" ]'

    # Applications > HTTP PROXY > GENERAL > Allow access to local destinations:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "DENY_LOCAL_DESTINATIONS" value [ "0" ]'

    # Applications > HTTP PROXY > GENERAL > IPv4 DNS lookups preferred:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_DNS_V4FIRST" value "1"'

    # Applications > HTTP PROXY > GENERAL > Logging (Syslog local):
    # Applications > HTTP PROXY > GENERAL > Logging (Statistics):
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_LOGGING" value [ "0" ]'

    # Applications > HTTP PROXY > Authentication exceptions:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_EXCEPTION_URL_LIST" value "0"'

    # function Set-STISettingsTransparentMode {
    # This only works after you have enabled SSL Interception!!

    # function Set-STISettingsSslInterception {
    # This only works after you have added a CA under certificate settings

    # Applications > HTTP PROXY > TRANSPARENT MODE > Transparent Mode:
    Invoke-SSHCommand -SSHSession $SFISession -Command 'extc value set application "http_proxy" variable "ENABLE_TRANSPARENT" value "1"'

    # Applications > HTTP PROXY > TRANSPARENT MODE > Add Transparent Rule:
    # Invoke-SSHCommand -SSHSession $SFISession -Command ''

    # Applications > IDS / IPS > CYBER DEFENSE CLOUD > Threat Intelligence Filter > Log and drop connection:
    if ($LoadDefaults -or $PSBoundParameters.ContainsKey('CyberDefenseCloud')) {
        switch ($CyberDefenseCloud) {
            'Deactivate' {
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied group set implied_group "12" active "0"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "12" implied_rule "0" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "12" implied_rule "1" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied group set implied_group "13" active "0"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "13" implied_rule "0" active "0"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "13" implied_rule "1" active "0"'
            }
            'Log' {
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied group set implied_group "12" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "12" implied_rule "0" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "12" implied_rule "1" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied group set implied_group "13" active "0"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "13" implied_rule "0" active "0"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "13" implied_rule "1" active "0"'
            }
            'LogAndDrop' {
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied group set implied_group "12" active "0"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "12" implied_rule "0" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "12" implied_rule "1" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied group set implied_group "13" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "13" implied_rule "0" active "1"'
                Invoke-SSHCommand -SSHSession $SFISession -Command 'rule implied rule set implied_group "13" implied_rule "1" active "1"'
            }
        }
    }
}

# TODO: This must not contain any defaults from ITCE, thus the entire IP address has to be "adjustable"!
function New-SFIVlan {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [SSH.SshSession]
        $SFISession,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [int]
        [ValidateScript({($_ -le 255) -and ($_ -ge 0)})]
        $SiteId,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName
        )]
        [string]
        [ValidateSet('A0','A1','A2','A3','eth0','eth1','eth2','eth3')]
        $Interface = 'A1',

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [int]
        [ValidateRange(0,4095)]
        $VlanId,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [string]
        $VlanName,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName
        )]
        [int]
        [ValidateRange(0,255)]
        $InterfaceIpFourthOktett = 1,

        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName
        )]
        [int]
        [ValidateRange(16,31)] # You can adjust this to suit your defaults
        $SubnetmaskSuffix = 24
    )

    process {
        Write-Verbose "Processing:"
        Write-Verbose "SiteId = $( $SiteId )"
        Write-Verbose "VlanParent = $( $interface ) ($( if ($PSBoundParameters.ContainsKey('VlanParent')) { 'specified' } else { 'default' } ))"
        Write-Verbose "VlanId = $( $VlanId )"
        Write-Verbose "VlanName = $( $VlanName )"
        Write-Verbose "InterfaceIpFourthOktett = $( $InterfaceIpFourthOktett ) ($( if ($PSBoundParameters.ContainsKey('InterfaceIpFourthOktett')) { 'specified' } else { 'default' } ))"
        Write-Verbose "SubnetmaskSuffix = $( $SubnetmaskSuffix ) ($( if ($PSBoundParameters.ContainsKey('SubnetmaskSuffix')) { 'specified' } else { 'default' } ))"

        Invoke-SSHCommand -SSHSession $SFISession -Command "interface new name `"$( $interface ).$( $vlanId )`" type `"VLAN`" flags [ ] options [ `"vlan_id=$( $vlanId )`" `"vlan_parent=$( $interface )`" ]"

        # TODO: check if the zone already exists and get ID of zone if so
        # IF zone already exists:
        # Invoke-SSHCommand -SSHSession $SFISession -Command "interface zone set id `"$( $zoneId )`" interface `"$( $interface ).$( $vlanId )`""
        # Invoke-SSHCommand -SSHSession $SFISession -Command "interface zone set id `"$( $zoneId )`" interface `"$( $interface ).$( $vlanId )`""
        # Invoke-SSHCommand -SSHSession $SFISession -Command "interface set name `"$( $interface ).$( $vlanId )`" flags [ ] options [ `"dyndns_hostname=`" `"dyndns_user=`" `"dyndns_password=*******`" `"dyndns_server=update.spdyn.de`" `"dyndns_mx=`" `"dyndns_ipv4=`" `"dyndns_ipv6=`" `"vlan_id=2`" `"mtu=1500`" `"fallback_dev=`" `"ping_check_host=`" `"ping_check_interval=`" `"ping_check_threshold=`" `"route_hint=`" `"dyndns_webresolver=`" ]"
        # If zone doesn't exist:
        Invoke-SSHCommand -SSHSession $SFISession -Command "interface zone new name `"$( $vlanName )`" interface `"$( $interface ).$( $vlanId )`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "interface zone new name `"firewall-$( $vlanName )`" interface `"$( $interface ).$( $vlanId )`" flags [ `"INTERFACE`" ]"

        Invoke-SSHCommand -SSHSession $SFISession -Command "node new name `"$( $vlanName )-network`" address `"$( $interface ).$( $vlanId )`" zone `"$( $vlanName )`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "node new name `"$( $vlanName )-interface`" address `"$( $interface ).$( $vlanId )`" zone `"firewall-$( $vlanName )`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "interface address new device `"$( $interface ).$( $vlanId )`" address `"10.$( $siteId ).$( $vlanId ).$( $interfaceIpFourthOktett )/$( $subnetmaskSuffix )`""
    }

    end {
        Write-Verbose 'Restarting services and saving changes...'

        Invoke-SSHCommand -SSHSession $SFISession -Command "appmgmt restart application `"dhcpd`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "appmgmt restart application `"dhcprelay`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "appmgmt restart application `"named`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "appmgmt restart application `"openvpn`""
        Invoke-SSHCommand -SSHSession $SFISession -Command "system config save"
        Invoke-SSHCommand -SSHSession $SFISession -Command "system update interface"
    }
}

# TODO: make pipeline capable
function Remove-SFIInterface {
    [CmdletBinding()]
    param (
        [Parameter( Mandatory, ValueFromPipelineByPropertyName )]
        [SSH.SshSession]
        $SFISession,

        # E. g. "A1.10"
        [Parameter( Mandatory, ValueFromPipelineByPropertyName )]
        [string]
        $InterfaceName
    )

    begin {
        Write-Verbose "Deletion of interface $( $InterfaceName ):"
        # Delete address from nodes/zones and thus unlink them from the interface before one can delete said interface:
        $NodeTable = Invoke-SSHCommand -SSHSession $SFISession -Command "node get"
        $Nodes = $NodeTable.Output.where({$_ -like "*$( $InterfaceName )*"})
        
        foreach ($n in $Nodes) {
            $nId = $n.split('|')[0].trim()
            $nName = $n.split('|')[1].trim()
            $nAddress = $n.split('|')[2].trim()
            $nZone = $n.split('|')[3].trim()
        
            Write-Verbose "Deletion of interface $( $InterfaceName ): Deleting node (node-ID = $( $nId ); node name = $( $nName ); node zone = $( $nZone ))..."
            Invoke-SSHCommand -SSHSession $SFISession -Command "node set id `"$( $nId )`" name `"$( $nName )`" address `"`" zone `"$( $nZone )`""
        }

        # Delete the interface:
        Write-Verbose "Deletion of interface $( $InterfaceName ): Deleting interface..."
        Invoke-SSHCommand -SSHSession $SFISession -Command "interface delete name `"$( $InterfaceName )`""
    }
    
    end {
        # Restart Services and save config:
        Write-Verbose 'Saving config...'
        Invoke-SSHCommand -SSHSession $SFISession -Command "system config save"
        Write-Verbose 'Updating interfaces...'
        Invoke-SSHCommand -SSHSession $SFISession -Command "system update interface"
    }
}

# TODO: Write ITCE defaults function. eth0.MTU = 1484 (FRITZ!Box)!
function Set-SFIInterface {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [SSH.SshSession]
        $SFISession,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [string]
        $InterfaceName,

        # TODO: Actually use this variable LOL
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName
        )]
        [integer]
        $MTU = 1500,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [ipaddress]
        $IPAddress,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [int]
        [ValidateRange('1,31')]
        $SubnetmaskSuffix
    )

    # Delete the old ip from the interface:
    Invoke-SSHCommand -SSHSession $SFISession -Command "interface address delete id `"$( $id )`"" # TODO: Find out ID of IP addresses on interfaces or maybe just delete all ip addresses.
    # Add the new ip to the interface:
    Invoke-SSHCommand -SSHSession $SFISession -Command "interface address new device `"$( $InterfaceName )`" address `"$( $IPAddress )/$( $SubnetmaskSuffix )`""
    
    # Save and apply interface settings:
    Invoke-SSHCommand -SSHSession $SFISession -Command "system config save"
    Invoke-SSHCommand -SSHSession $SFISession -Command "system update interface"
}

# TODO: function to delete portfilter groups and rules (e. g. the default ones)

function New-SFIPortfilterGroup {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [SSH.SshSession]
        $SFISession,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [int]
        $ID,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName
        )]
        [string]
        $Name
    )

    Invoke-SSHCommand -SSHSession $SFISession -Command "rule group new name `"$( $name )`""
    Invoke-SSHCommand -SSHSession $SFISession -Command "rule group set id `"$( $id )`" name `"$( $name )`""
}

# TODO: enable this function to work with pipeline input
function New-SFINetworkObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [SSH.SshSession]
        $SFISession,

        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [ipaddress]
        $Address,

        [Parameter()]
        [string]
        $Zone = 'external'
    )
    
    Invoke-SSHCommand -SSHSession $SFISession -Command "node new name `"$( $name )`" address `"$( $address )/32`" zone `"$( $zone )`""
}

function New-SFINetworkObjectGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [SSH.SshSession]
        $SFISession,

        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter()]
        [string[]]
        $Member
    )

    if ($Member) {
        Invoke-SSHCommand -SSHSession $SFISession -Command "node group new name `"$( $name )`""
        foreach ($m in $Member) {
            Invoke-SSHCommand -SSHSession $SFISession -Command "node group add name `"$( $name )`" nodes `"$( $m )`""
        }
    } else {
        Invoke-SSHCommand -SSHSession $SFISession -Command "node group new name `"$( $name )`""
    }
}

# Documentation for rules: https://wiki.securepoint.de/Rule_cli_v11
# TODO: add parameter sets
function New-SFIPortfilterRule {
    [CmdletBinding()]
    param (
        [Parameter( Mandatory, ValueFromPipelineByPropertyName )]
        [SSH.SshSession]
        $SFISession,

        [Parameter( Mandatory, ValueFromPipelineByPropertyName )]
        [string]
        $Group,

        [Parameter( Mandatory, ValueFromPipelineByPropertyName )]
        [string]
        $Source,

        [Parameter( Mandatory, ValueFromPipelineByPropertyName )]
        [string]
        $Destination = 'internet',

        [Parameter( ValueFromPipelineByPropertyName )]
        [string]
        $Service = 'any',

        # TODO: Solve parameter dependencies (regarding natting) via dynamic parameters: https://stackoverflow.com/questions/49805889/powershell-validateset-between-separate-parameter-sets-using-same-parameter
        [Parameter()]
        [string]
        [ValidateSet('HIDENAT', 'HIDENAT_EXCLUDE', 'DESTNAT')]
        $NatMode = 'HIDENAT',

        [Parameter()]
        [string]
        $NatNode = 'external-interface',

        [Parameter()]
        [string]
        $NatService,

        [Parameter()]
        [string]
        [ValidateSet('NONE', 'LOG_ALL', 'LOG')]
        $LogLevel = 'LOG_ALL',

        [Parameter()]
        [string]
        $Route = '',

        [Parameter()]
        [string]
        $QOS = '',

        [Parameter()]
        [string]
        $Timeprofile = '',

        [Parameter()]
        [string]
        $Comment = '',

        [Parameter()]
        [string]
        [ValidateSet('accept')] # TODO
        $Action = 'accept'
    )

    process {
        switch ($LogLevel) {
            'LOG_ALL' { $log = '"LOG_ALL" ' }
            'LOG' { $log = '"LOG" ' }
            'NONE' { $log = $null }
        }
    
        switch ($action) {
            'accept' { $actionText = '"ACCEPT" ' }
        }

        $flags = ''
        $flags += "`"$( $NatMode )`" "
        $flags += $actionText
        if ($log) { $flags += $log }

                  # rule new group "nicht einsortiert" src "internal-network" dst "internet" service "any" comment "" flags [ "LOG_ALL" "FULLCONENAT" "ACCEPT" ] nat_node "external-interface"
                  # rule new group "clients" src "clients-network" dst "internet" service "any" comment "" flags [ "HIDENAT" "ACCEPT" ] nat_node "external-interface"
                  # rule new group "Milon" src "milon-network" dst "milon-interface" service "any" comment "" flags [ "LOG_ALL" "ACCEPT" ]
        $command = "rule new group `"$( $group )`" src `"$( $source )`" dst `"$( $destination )`" service `"$( $service )`" flags [$( $flags )] nat_node `"$( $NatNode )`""

        Write-Verbose 'Processing:'
        Write-Verbose "group = $( $group )"
        Write-Verbose "source = $( $source )"
        Write-Verbose "destination = $( $destination )"
        Write-Verbose "service = $( $service )"
        Write-Verbose "route = $( $route )"
        Write-Verbose "qos = $( $qos )"
        Write-Verbose "timeprofile = $( $timeprofile )"
        Write-Verbose "comment = $( $comment )"
        Write-Verbose "flags = $( $flags )"
        Write-Verbose "NatNode = $( $NatNode )"
        Write-Verbose "Full command = $( $command )"

        # TODO: This is way to long. Do Splatting or something.
        Invoke-SSHCommand -SSHSession $SFISession -Command $command
    }
    
    end {
        Write-Verbose 'Applying changes...'
        Invoke-SSHCommand -SSHSession $SFISession -Command  'system update rule'
    }
}
