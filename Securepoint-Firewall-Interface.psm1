# To import this Module: Import-Module .\Securepoint-Firewall-Interface.psm1

# TODO:
# Add logging.
# Check if local IP is on 192.168.175.0/24 network.
# Add capability to load configuration files.
# Add function to check if default settings are set/settings are correct (check if cloud backup active).

# Manual Tasks:
# Initial setup: assign license, name device, set date
# Activate cloud backup

function Set-SFISettings {
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

#region INITIALIZATION
<# 
    Libraries, Modules, ...
#>

if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Log "Installing Posh-SSH..."
    Install-Module -Name Posh-SSH -Force -Confirm:$false -Scope CurrentUser
}
if (-not (Get-Module -Name Posh-SSH)) {
    Log "Importing Posh-SSH..."
    Import-Module -Name Posh-SSH
}
if (Get-Module -Name Posh-SSH) {
    Log "Found Posh-SSH. Starting..."

    #endregion INITIALIZATION
    #region DECLARATIONS
    <#
        Declare local variables and global variables
    #>

    $cred = Get-Credential
    $s = New-SSHSession -ComputerName 192.168.175.1 -Credential $cred -AcceptKey

    #endregion DECLARATIONS
    #region FUNCTIONS
    <# 
        Declare Functions
    #>

    function Write-ConsoleLog {
        <#
        .SYNOPSIS
        Logs an event to the console.
        
        .DESCRIPTION
        Writes text to the console with the current date (US format) in front of it.
        
        .PARAMETER Text
        Event/text to be outputted to the console.
        
        .EXAMPLE
        Write-ConsoleLog -Text 'Subscript XYZ called.'
        
        Long form
        .EXAMPLE
        Log 'Subscript XYZ called.
        
        Short form
        #>
        [alias('Log')]
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true,
            Position = 0)]
            [string]
            $Text
        )

        # Save current VerbosePreference
        $VerbosePreferenceBefore = $VerbosePreference

        # Enable verbose output
        $VerbosePreference = 'Continue'

        # Write verbose output
        Write-Verbose "$( Get-Date -Format 'MM/dd/yyyy HH:mm:ss' ) - $( $Text )"

        # Restore current VerbosePreference
        $VerbosePreference = $VerbosePreferenceBefore
    }

    function Invoke-SFICommand {
        # Abbreviation: SFI = Securepoint Firewall Interface
        [CmdletBinding()]
        [Alias('invoke')]
        param (
            [Parameter(
                Mandatory = $false,
                Position = 0
            )]
            [System.Object]
            $Session,

            [Parameter(Mandatory = $true, Position = 1)]
            [string]
            $Command
        )

        $return = Invoke-SSHCommand -SSHSession $session -Command $command

        if ($return.ExitStatus -eq 0) {
            return $true
        } else {
            return $false
        }
    }

    function Set-SFISettingsNetwork {

        function Set-SFISettingsApplianceSettings {

            function Set-SFISettingsFirewall {  
                [CmdletBinding()]
                param (
                    [Parameter(
                        Mandatory = $false,
                        Position = 0
                    )]
                    [string]
                    $GlobalContactPerson = 'IT-Center Engels'
                )
                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > FIREWALL > Global contact person:
                invoke $s "extc global set variable `"GLOB_ADMIN_NAME`" value [ `"$APPLIANCESETTINGS_APPLIANCESETTINGS_GlobalContactPerson`" ]"

                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > FIREWALL > Global email address:
                invoke $s 'extc global set variable "GLOB_ADMIN_EMAIL" value [ "support@itc-engels.de" ]'

                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > FIREWALL > Report language:
                invoke $s 'extc global set variable "GLOB_LANGUAGE" value [ "DE" ]'
            }
            
            function Set-SFISettingsDNS {
                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > DNS SERVER > Check Nameserver prior to local cache:
                invoke $s 'extc global set variable "GLOB_NAMESERVER_ASK_REMOTE_FIRST" value "1"'

                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > DNS SERVER > Primary Nameserver >, Secondary Nameserver:
                invoke $s 'extc global set variable "GLOB_NAMESERVER" value [ "8.8.8.8" "1.1.1.1" ]'
            }

            function Set-SFISettingsTimezone {
                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > TIME SETTINGS > Timezone:
                invoke $s 'extc global set variable "GLOB_TIMEZONE" value [ "Europe/Berlin" ]'

                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > TIME SETTINGS > NTP Server:
                invoke $s 'extc global set variable "GLOB_TIMEZONE" value [ "Europe/Berlin" ]'
            }

            function Set-SFISettingsWebserver {
                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > WEBSERVER
                # Coming soon
            }

            function Set-SFISettingsAdvancedSettings {
                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > ADVANCED SETTINGS > Maximum Active Connections:
                invoke $s 'extc value set application "securepoint_firewall" variable "IPCONNTRACK" value [ "0" ]'

                # NETWORK > APPLIANCE SETTINGS > APPLIANCE SETTINGS > ADVANCED SETTINGS > Last Rule Logging:
                invoke $s 'extc value set application "securepoint_firewall" variable "LASTRULE_LOGGING" value [ "1" ]'
            }

            function Set-SFISettingsProxy {
                # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > IP Address:
                invoke $s 'extc global set variable "GLOB_HTTP_PARENT_PROXY_ADDR" value [ "" ]'

                # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > Port:
                # Coming soon
                
                # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > User:
                # Coming soon
                
                # NETWORK > APPLIANCE SETTINGS > SYSTEM-WIDE PROXY > Password:
                # Coming soon    
            }
                
            function Set-SFISettingsAdministration {
                # NETWORK > APPLIANCE SETTINGS > ADMINISTRATION:
                invoke $s 'extc value set application "spresolverd" variable [ "MANAGER_HOST_LIST" ] value [ "centervision.spdns.de" ]'
            }
            
            function Set-SFISettingsSyslog {
                # NETWORK > APPLIANCE SETTINGS > SYSLOG > Log the UTM hostname in the syslog messages:
                invoke $s 'extc value set application "syslog" variable "WRITE_HOST" value [ "0" ]'
            }
            
            function Set-SFISettingsSNMP {
                # NETWORK > APPLIANCE SETTINGS > SNMP > SNMP Version:
                invoke $s 'extc value set application "snmpd" variable "ENABLE_SNMP_V1" value [ "0" ]'

                # NETWORK > APPLIANCE SETTINGS > SNMP > SNMP Version:
                invoke $s 'extc value set application "snmpd" variable "ENABLE_SNMP_V2" value [ "0" ]'

                # NETWORK > APPLIANCE SETTINGS > SNMP > SNMP Version:
                invoke $s 'extc value set application "snmpd" variable "ENABLE_SNMP_V3" value [ "0" ]'
            }

        }

        function Set-SFISettingsQos {
            # NETWORK > QOS > NETWORK INTERFACES > GENERAL > Mode:
            invoke $s 'extc global set variable "GLOB_QOS_MODE" value [ "auto" ]'
            invoke $s 'extc global set variable "GLOB_QOS_INTERFACE" value [ "" ]'
        }

    }

    function Set-SFISettingsApplications {
        
        function Set-STISettingsHttpProxy {
            
            # Applications > HTTP PROXY > GENERAL > Proxy Port:
            invoke $s 'extc value set application "http_proxy" variable "PROXY_PORT" value [ "8080" ]'

            # Applications > HTTP PROXY > GENERAL > Outgoing Address:
            invoke $s 'extc value set application "http_proxy" variable "OUTGOING_ADDR" value [ "" ]'

            # Applications > HTTP PROXY > GENERAL > Forward requests to system-wide parent proxy:
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_FORWARD" value "0"'

            # Applications > HTTP PROXY > GENERAL > Authentication method:
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_AUTH_LOCAL" value "0"'
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_AUTH_RADIUS" value "0"'
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_AUTH_NTLM" value "0"'
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_AUTH_NTLM" value "0"'

            # Applications > HTTP PROXY > GENERAL > Allow access only from local sources:
            invoke $s 'extc value set application "http_proxy" variable "RESTRICT_CLIENT_ACCESS" value [ "1" ]'

            # Applications > HTTP PROXY > GENERAL > Allow access to local destinations:
            invoke $s 'extc value set application "http_proxy" variable "DENY_LOCAL_DESTINATIONS" value [ "0" ]'

            # Applications > HTTP PROXY > GENERAL > IPv4 DNS lookups preferred:
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_DNS_V4FIRST" value "1"'

            # Applications > HTTP PROXY > GENERAL > Logging (Syslog local):
            # Applications > HTTP PROXY > GENERAL > Logging (Statistics):
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_LOGGING" value [ "0" ]'

            # Applications > HTTP PROXY > Authentication exceptions:
            invoke $s 'extc value set application "http_proxy" variable "ENABLE_EXCEPTION_URL_LIST" value "0"'

            function Set-STISettingsTransparentMode {
                # This only works after you have enabled SSL Interception!!
                
                
            }

            function Set-STISettingsSslInterception {
                # This only works after you have added a CA under certificate settings

                # Applications > HTTP PROXY > TRANSPARENT MODE > Transparent Mode:
                invoke $s 'extc value set application "http_proxy" variable "ENABLE_TRANSPARENT" value "1"'

                # Applications > HTTP PROXY > TRANSPARENT MODE > Add Transparent Rule:
                invoke $s ''
            }
        }

        function Set-STISettingsIdsIps {
            [CmdletBinding()]
            param (
                [Parameter(
                    Mandatory = $false,
                    Position = 0
                )]
                [ValidateSet('Deactivate','Log','LogAndDrop')]
                [string]
                $CyberDefenseCloud = 'LogAndDrop'
            )

            function Set-STISettingsCyberDefenseCloud {
                [CmdletBinding()]
                param (
                    [Parameter(
                        Mandatory = $false,
                        Position = 0
                    )]
                    [ValidateSet('Deactivate','Log','LogAndDrop')]
                    [string]
                    $Status = 'LogAndDrop'
                )
                
                # Applications > IDS / IPS > CYBER DEFENSE CLOUD > Threat Intelligence Filter > Log and drop connection:
                switch ($status) {
                    'Deactivate' {
                        invoke $s 'rule implied group set implied_group "12" active "0"'
                        invoke $s 'rule implied rule set implied_group "12" implied_rule "0" active "1"'
                        invoke $s 'rule implied rule set implied_group "12" implied_rule "1" active "1"'
                        invoke $s 'rule implied group set implied_group "13" active "0"'
                        invoke $s 'rule implied rule set implied_group "13" implied_rule "0" active "0"'
                        invoke $s 'rule implied rule set implied_group "13" implied_rule "1" active "0"'
                    }
                    'Log' {
                        invoke $s 'rule implied group set implied_group "12" active "1"'
                        invoke $s 'rule implied rule set implied_group "12" implied_rule "0" active "1"'
                        invoke $s 'rule implied rule set implied_group "12" implied_rule "1" active "1"'
                        invoke $s 'rule implied group set implied_group "13" active "0"'
                        invoke $s 'rule implied rule set implied_group "13" implied_rule "0" active "0"'
                        invoke $s 'rule implied rule set implied_group "13" implied_rule "1" active "0"'
                    }
                    'LogAndDrop' {
                        invoke $s 'rule implied group set implied_group "12" active "0"'
                        invoke $s 'rule implied rule set implied_group "12" implied_rule "0" active "1"'
                        invoke $s 'rule implied rule set implied_group "12" implied_rule "1" active "1"'
                        invoke $s 'rule implied group set implied_group "13" active "1"'
                        invoke $s 'rule implied rule set implied_group "13" implied_rule "0" active "1"'
                        invoke $s 'rule implied rule set implied_group "13" implied_rule "1" active "1"'
                    }
                }
            }

            Set-STISettingsCyberDefenseCloud -Status $CyberDefenseCloud
        }

    }

    #endregion FUNCTIONS
    #region EXECUTION
    <# 
        Function entry point
    #>

    Set-SFISettingsNetwork
    Set-SFISettingsApplications

    #endregion EXECUTION
    }
}
