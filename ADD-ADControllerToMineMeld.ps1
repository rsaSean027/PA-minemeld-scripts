<#
    Author: Sean Engelbrecht
    Version: 2018.04.13.0.2
#>
<#
.Synopsis
    Update Active Directory objects utilized by Palo Alto Firewalls
#>

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
# MineMeld server
$mineMeldSrv = "minemeld.net.dvn"
# indicatorOutput is the output/feed list name that the indicators should exist in
$indicatorOutput = "Corp_Domain_Controller_List"
# IndicatorList is the name of the input feed/prototype list that the indicators should be added to 
$IndicatorList = "Corp_Domain_Controllers"
$url = "https://" + $mineMeldSrv + "/feeds/" + $indicatorOutput
$currentList = Invoke-WebRequest $url
$msgSpaces = " " * 3
Function add-MMIndicator ($indicator)
{
    # Check if indicator already exist
    if ( -not $currentList.Content.Contains($indicator) )
    {
        #Credentials can be passed using basic authentication
        #   * Simply base46 encode {username}:{password} and add that string to the headers
        #   * Be sure to include the ':' between the strings
        #   * $userPass = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($user):$($passwd)"))
        $userPass = ""
        # Adding the Authentication string to the post request headers
        $headers = @{
            Authorization = 'Basic ' +  $userPass
        }
        # to add date and time to the comments field for each indicator
        $dateTime = get-date -format F
        $Comment = 'Indicator added with Powershell on ' + $dateTime  + ' - by ' + $env:username + ' from ' + $env:COMPUTERNAME 
        # HTTP Post variables required for adding indicator 
        $indicatorArr = @{
            indicator = $indicator
            type = 'IPv4'
            share_level = 'red'
            comment = $comment
        }
        $json = $indicatorArr | ConvertTo-Json
        $url = "https://" + $mineMeldSrv + "/config/data/" + $IndicatorList + "_indicators/append?h=" + $IndicatorList
        $response = Invoke-RestMethod $url -Method Post -Body $json -ContentType 'application/json' -Headers $headers
        $response
        $msg = "Success - $Indicator added to minemeld."
        Write-Host $msgSpaces $msg -ForegroundColor Green
    }
    else
    {
        $errMsg = "Existing Entry - $Indicator already in the minemeld, indicator not added."
       
        Write-Host $msgSpaces $errMsg -ForegroundColor Yellow
    }
}
Get-ADDomainController -Filter * | foreach {
    $ip = $_.IPv4Address -replace ' ',''
    # Set variable to enter worker block
    $validIP = ($ip -As [IPAddress]) -As [Bool]
    If ( -not $validIP )
    {
        $errMsg = "Error - $ip is not a valid IP address, indicator not added."
        Write-Host $msgSpaces $errMsg -ForegroundColor Red
    }
    else
    {
        # If IP address is valid call the add-MMIndicator Function
        add-MMIndicator($ip)
    }
}