<#
Author: Sean Engelbrecht
Version: 2018.04.26.0.11

****************************************
***          Version History         ***
****************************************
Version: 2018.04.26.0.11
    Original Code

****************************************
#>
Function add-MineMeldZoneExeption
{
    <#
    .SYNOPSIS
        Add indicators to MineMeld feeds utilized by Palo Alto Firewalls
    .DESCRIPTION
        This cmdlet can be utilized to add Indicators (Ip addresses) to designated lists in minemeld ( A Palo Alto open source threat aggregation tool).
        Mandatory parameters for this function include: Indicator.
        Optional parameters for this function include: Server, FeedList, BypassSSLError, checkIndicator
    .PARAMETER Server
        This parameter contains the ip-address or FQDN of the MineMeld server.
    .PARAMETER Indicator
        This parameter contains the Indicator (IP Address) to be added to the MineMeld server.
    .PARAMETER FeedList
        This parameter contains the name of the output stream/list where the indicator should be added.
    .PARAMETER BypassSSLError
        If this parameter is present self-signed certificate errors will be bypassed. 
    .PARAMETER checkIndicator
        Switch to check the existance of indicator, if the parameter is present the indicator will not be added to any lists. Only for validation/verification.
    .EXAMPLE
	    add-MineMeldZoneExeption -Indicator 192.168.100.123
        This will add 192.168.100.123 to the default list.
    .EXAMPLE
	    add-MineMeldZoneExeption -Indicator 192.168.100.123 -checkIndicator
        This will check if 192.168.100.123 is already included in the default list.
    .EXAMPLE
	    add-MineMeldZoneExeption -Indicator 192.168.100.124 -FeedList EDL-Server-Exeption2
        This will add 192.168.100.124 to the EDL-Server-Exeption2. The EDL-Server-Exeption2 list will be updated to include 192.168.100.124.
    .EXAMPLE
	    add-MineMeldZoneExeption -Indicator 192.168.100.124 -FeedList EDL-Server-Exeption3 -checkIndicator
        This will check if 192.168.100.124 is already included in EDL-Server-Exeption3. No changes are made to the existing list.
    .EXAMPLE
	    add-MineMeldZoneExeption -Indicator server123.corp.net -FeedList EDL-Server-Exeption2
        This will perform a lookup on server123.corp.net. If the entry has an associated dns entry, the IP address will be added to the EDL-Server-Exeption2. The EDL-Server-Exeption2 will be updated to include the IP address for server123.corp.net.
    .EXAMPLE
	    add-MineMeldZoneExeption -Indicator server123.corp.net -FeedList EDL-Server-Exeption2 -checkIndicator
        This will perform a lookup on server123.corp.net. If the entry has an associated dns entry, the IP address will be checked against the EDL-Server-Exeption2. No changes are made to the existing list.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="IP-Address or FQDN of MineMeld Server:",
                   Position=2)]
        [String]
        $Server = "",
        [parameter(Mandatory=$false,
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Output stream of threat feed:",
                   Position=1)]
        [String]
        [validateSet("EDL-Server-Exeption1", "EDL-Server-Exeption2", "EDL-Server-Exeption3")]
        $FeedList = "EDL-Server-Exeption1",
        [parameter(Mandatory=$true, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Threat indicator to Add:",
                   Position=0)]
        [String]
        $Indicator,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Bypass any SSL Errors:",
                   Position=3)]
        [switch]
        $BypassSSLError,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Check the existance of an indicator:",
                   Position=4)]
        [switch]
        $checkIndicator,
        [parameter(Mandatory=$false, 
                   valueFromPipelineByPropertyName=$true, 
                   HelpMessage="Check the existance of an indicator:",
                   Position=5)]
        [switch]
        $authHeader
    )
    Begin
    {
        
        #Set Initial Variables and check for errors
        If ($BypassSSLError.IsPresent)
        {
            if ( -not ("TrustAllCertsPolicy" -as [type]) )
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

        }
        # Minemeld FeedList to Indicator list mapping
        # "output feed" = "input prototype/list"
        $feedMap = @{
            "EDL-Server-Exeption1" = "Server-Exeption1"
            "EDL-Server-Exeption2" = "Server-Exeption2"
            "EDL-Server-Exeption3" = "Server-Exeption3"
        }
    }
    Process
    {
        # Minemeld lookup url
        # No authentication or authorization required
        $url =  "https://" + $Server + "/feeds/" + $FeedList
        $validIP = $false
        $msgSpaces = " " * 3
        Try
        {
            # Clear global variable Error
            $Error.Clear()
            # Track stage in script deployment, for custom error messages
            $stage = 1
            # Reverse lookup for Indicatiors
            $fqdnResult = Resolve-DnsName -Name $Indicator -ErrorAction Ignore
            if ([string]::IsNullOrEmpty($fqdnResult))
            {
                # If no lookup exists inform the user
                $errMsg = "Warning - $Indicator has No DNS entry."
                Write-Host $msgSpaces $errMsg -ForegroundColor White -BackgroundColor DarkYellow
                # Set variable to enter worker block
                $validIP = ($Indicator -As [IPAddress]) -As [Bool]
                If ( -not $validIP )
                {
                    $errMsg = "Error - $Indicator is not a valid IP address, indicator not added."
                    Write-Host $msgSpaces $errMsg -ForegroundColor Red
                }
            }
            else
            {
                switch($fqdnResult.type)
                {
                    "A" {
                            $Indicator = $fqdnResult.IPAddress
                            $dnsName = $fqdnResult.Name
                        }
                    "PTR"{ $dnsName = $fqdnResult.NameHost }
                }

                # Set variable to enter worker block
                $validIP = ($Indicator -As [IPAddress]) -As [Bool]
                If ( -not $validIP )
                {
                    $errMsg = "Error - $Indicator is not a valid IP address, indicator not added."
                    Write-Host $msgSpaces $errMsg -ForegroundColor Red
                }
            }
            If ( $validIP )
            {
                $stage = 2         
                # Retrieve the current feed list, this prevents duplicate entries.
                $currentList = Invoke-WebRequest $url -TimeoutSec 30
                $stage = 3
                # Check if indicator exists
                if ( -not $currentList.Content.Contains($Indicator) )
                {
                    if ( -not $checkIndicator)
                    {
                        $IndicatorList = $feedMap.$feedList
                        $IndicatorList = $IndicatorList.trim()
                        # to add date and time to the comments field for each indicator
                        $dateTime = get-date -format F
                        $Comment = 'Indicator added with Powershell on ' + $dateTime  + ' - by ' + $env:username + ' from ' + $env:COMPUTERNAME
                        # Array that will be converted to JSON format for POST request
                        $Type = "IPv4"
                        $ShareLevel = "red"
                        # HTTP Post variables required for adding indicator 
                        $indicatorArr = @{
                            indicator = "$Indicator"
                            type = "$Type"
                            share_level = "$ShareLevel"
                            comment = "$Comment"
                        }
                        $requestBody = $indicatorArr | ConvertTo-Json
                        # rest api url
                        $url = "https://" + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList
                        #$url = "https://api." + $Server + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList
                        if ( $authHeader )
                        {
                            #Credentials can be passed using basic authentication
                            #   * Simply base46 encode {username}:{password} and add that string to the headers
                            #   * Be sure to include the ':' between the strings
                            #   * $userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($user):$($passwd)"))
                            $userPass = ""
                            # Adding the Authentication string to the post request headers
                            $Headers = @{
                                Authorization = 'Basic ' +  $userPass
                            }
                            # ReST call to update list
                            $Response = Invoke-RestMethod $url -Method Post -Body $requestBody -ContentType 'application/json' -Headers $Headers
                        }
                        else
                        {
                            # ReST call to update list
                            $Response = Invoke-RestMethod $url -Method Post -Body $requestBody -ContentType 'application/json'
                        }
                        if ([string]::IsNullOrEmpty($dnsName))
                        {
                            $msg = "Success - $Indicator added to minemeld."
                        }
                        else
                        {
                            $msg = "Success - " + $Indicator + " ( " + $dnsName + " ) added to minemeld."
                        }
                    }
                    else
                    {
                        if ([string]::IsNullOrEmpty($dnsName))
                        {
                            $msg = "Check Indicator - $Indicator not in minemeld."
                        }
                        else
                        {
                            $msg = "Check Indicator - " + $Indicator + " ( " + $dnsName + " ) not in minemeld."
                        }
                    }
                    Write-Host $msgSpaces $msg -ForegroundColor Green
                }
                else
                {
                    if ( $checkIndicator)
                    {
                        if ([string]::IsNullOrEmpty($dnsName))
                        {
                            $errMsg = "Check Indicator - $Indicator already in the minemeld."
                        }
                        else
                        {
                            $errMsg = "Check Indicator - " + $Indicator + " ( " + $dnsName + " ) already in the minemeld."
                        }
                    }
                    else
                    {
                        if ([string]::IsNullOrEmpty($dnsName))
                        {
                            $errMsg = "Existing Entry - $Indicator already in the minemeld, indicator not added."
                        }
                        else
                        {
                            $errMsg = "Existing Entry - " + $Indicator + " ( " + $dnsName + " ) already in the minemeld, indicator not added."
                        }
                    }
                    Write-Host $msgSpaces $errMsg -ForegroundColor Yellow
                }
            }
        }
        catch
        {
            switch ($stage)
            {
                1 { throw "No DNS entry for the following indicator: $Indicator" }
                2 { 
                    if ( $Error.Item(0).toString().Contains("Could not establish trust relationship for the SSL" ))
                    {
                        throw "Error: Could not establish trust relationship for the SSL/TLS secure channel for '$url', Indicators cannot be added at this time."
                    }
                    else
                    {
                        throw "Error retrieving data from '$url', Indicators cannot be added at this time."
                    }
                   }
                3 { 
                     if ( $Error.Item(0).toString().Contains("Could not establish trust relationship for the SSL" ))
                    {
                        throw "Error: Could not establish trust relationship for the SSL/TLS secure channel for '$url', Indicators cannot be added at this time."
                    }
                    else
                    {
                        throw "Error adding indicator, ($Indicator) to $IndicatorList on $Server.
                        Try including an authentication header."
                    }
                  }
                default {"Unknown Error!"}
            }
        }
    }
    end
    {
        #Print function status and cleanup
        Write-Verbose "Done"
    }
}