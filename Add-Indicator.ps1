<#
Author: Sean Engelbrecht
Version: 2017.02.02.0.4

****************************************
***          Version History         ***
****************************************
Version: 2017.02.02.0.4
    Fix: Help Content
            Typo's in the Eaxmple documents 

Version: 2017.02.02.0.3
    Fix: Programming logic
            Corrected logic flow on verifying the indicator

    Enhance: Error messages
                Error output will alert if ssl error was reason for failure.

Version: 2017.01.04.0.2
    Fix: Help Content
            Get-Help add-MineMeldIndicator -Full would not properly display information
    Fix: Variable Types
            Some variables were set to String Arrays, corrected not all string variables are type string

Version: 2016.12.28.0.1
    Original Code

****************************************
#>
Function add-MineMeldIndicator
{
    <#
    .SYNOPSIS
        Add indicators to MineMeld feeds utilized by Palo Alto Firewalls
    .DESCRIPTION
        This cmdlet can be utilized to add threat indicators to fields listed in minemeld ( A Palo Alto open source threat aggregation tool).
        Mandatory functions for this function include; Server, FeedList, IndicatorList, Type and Indicator.
    .PARAMETER Server
        This Parameter contains the ip-address or FQDN of the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Indicator
        This Parameter contains the Indicator to be added to the MineMeld server.
        Parameter has no Default Value
    .PARAMETER Type
        This Parameter contains the type of indicator to be added to the the MineMeld server (IPv4 or URL).
        Parameter Default Value: URL
    .PARAMETER IndicatorList
        This Parameter contains the name of the input stream/list where the indicator should be added.
        Parameter Default Value: Malware_List
    .PARAMETER FeedList
        This Parameter contains the name of the output stream/list where the indicator should be added.
        Parameter Default Value: HC_URL_List
    .PARAMETER IncludeSubDomain
        If this parameter is present and the Type is URL an additional indicator will be added containing a wildcard token.
    .PARAMETER BypassSSLError
        If this parameter is present self-signed certificate errors will be bypassed.
    .EXAMPLE
	    add-MineMeldIndicator -Server 192.168.1.10 -Indicator "evil.com"
        This will add the url evil.com to the default list on minemeld server (192.168.1.10)
    .EXAMPLE
	    add-MineMeldIndicator -Server 192.168.1.10 -Indicator "evil.com" -IncludeSubDomain
        Will add the url's evil.com and *.evil.com to the default list on minemeld server (192.168.1.10)
    .EXAMPLE
	    add-MineMeldIndicator -Server 192.168.1.10 -Indicator "evil.com" -BypassSSLError
        This will add the url evil.com to the default list on minemeld server (192.168.1.10) and bypass and SSL certificate errors caused by self-signed SSL certs.
    .EXAMPLE
	    add-MineMeldIndicator -Server 192.168.1.10 -Indicator "172.16.12.21" -Type IPv4 -FeedList "mm_dc_list" -IndicatorList "DC_IP_List"
        Will Add ip address 172.16.21.21 to mm_dc_list on minemeld server (192.168.1.10)
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="IP-Address or FQDN of MineMeld Server:",
                   Position=0)]
        [String]
        $Server,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Output stream of threat feed:",
                   Position=3)]
        [String]
        $FeedList = "HC_URL_List",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Input stream to add threat indicator to:",
                   Position=4)]
        [String]
        $IndicatorList = "Malware_List",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Indicator type[IPv4 or URL]:",
                   Position=1)]
        [string]
        [validateSet("IPv4","URL")]
        $Type = "URL",
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Indicator type[IPv4 or URL]:",
                   Position=5)]
        [string]
        [validateSet("green","yellow","red")]
        $ShareLevel = "red",
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Threat indicator to Add:",
                   Position=2)]
        [String]
        $Indicator,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Bypass any SSL Errors:",
                   Position=7)]
        [switch]
        $BypassSSLError,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Include wildcard character to for subdomains *.evil.com:",
                   Position=6)]
        [switch]
        $IncludeSubDomain
    )
    Begin
    {
        #Set Initial Variables and check for errors
        If ($BypassSSLError)
        {
            add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        # Variabel used to the while loop needed to include a wildcard for subdomains
        $exitLoop = $false
    }
    Process
    {
        $url =  "https://" + $Server + "/feeds/" + $FeedList
        Try
        {
            $Error.Clear()
            $stage = 1
            # Retrieve the current feed list, this prevents duplicate entries.
            $currentList = Invoke-WebRequest $url -TimeoutSec 30
            $stage = 2
            #Credentials can be passed using basic authentication
            #   * Simply base46 encode {username}:{password} and add that string to the headers
            #   * Be sure to include the ':' between the strings
            # $userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($user):$($passwd)"))
            # OR
            # $userPass = '{Place the base-64 output of [USERNAME]:[PASSWORD] HERE}'
            # Adding the Authentication string to the post request headers
            $Headers = @{
                Authorization = 'Basic ' +  $userPass
            }
            while ( -not $exitLoop)
            {
                # Check if indicator exists
                if ( -not $currentList.Content.Contains($Indicator) )
                {
                    # to add date and time to the comments field for each indicator
                    $dateTime = get-date -format F
                    $Comment = 'Indicator added with Powershell on ' + $dateTime 
                    # Array that will be converted to JSON format for POST request
                    $indicatorArr = @{
                        indicator = "$Indicator"
                        type = "$Type"
                        share_level = "$ShareLevel"
                        comment = "$Comment"
                    }
                    $requestBody = $indicatorArr | ConvertTo-Json
                    $url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList
                    $Response = Invoke-RestMethod $url -Method Post -Body $requestBody -ContentType 'application/json' -Headers $Headers
                    Write "The Following Indicator was added: $indicator"
                }
                else
                {
                    Write-Verbose "The Following Indicator was skipped, already in the list: $indicator"
                }
                if ( "$Type" -eq "URL" )
                    {
                        # Process structure for URL Indicators
                        if ( ($IncludeSubDomain -and $Indicator.Contains("*.") ) -or -not $IncludeSubDomain )
                        {
                            # If the wildcard has been processed already, or there is no need to include sub-domains, exit the loop.
                            $exitLoop = $true
                        }
                        else
                        # Since sub-domains are to be included, loop back around and add additional indicator with wildcard token.
                        {
                            $Indicator = "*.$Indicator"
                            $stage = 3
                        }
                    }
                    else
                    # If the Indicator is an IPv4 type, simply exit the loop.
                    {
                        $exitLoop = $true
                    }
            }
        }
        catch
        {
            switch ($stage)
            {
                1 { 
                    if ( $Error.Item(0).toString().Contains("Could not establish trust relationship for the SSL" ))
                    {
                        throw "Error: Could not establish trust relationship for the SSL/TLS secure channel for '$url', Indicators cannot be added at this time."
                    }
                    else
                    {
                        throw "Error retrieving data from '$url', Indicators cannot be added at this time."
                    }
                  }
                2 { throw "Error adding Indicator, ($Indicator) to $IndicatorList on $Server." }
                3 { throw "Error adding Wildcard Indicator, ($Indicator) to $IndicatorList on $Server." } 
                default {"Unknown Error... Please Help!"}
            }
        }
    }
    end
    {
        #Print function status and cleanup
        Write-Verbose "Done"
    }
}