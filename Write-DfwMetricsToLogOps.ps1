<#
.SYNOPSIS
    This script runs commands locally on ESXi hosts to gather NSX DFW metrics.

.DESCRIPTION
    This script runs commands locally on ESXi hosts to gather NSX DFW metrics.
    A shell scripts is passed through an SSH session to the hosts and run locally.
    Result of the shell scripts are written to the syslog.log of each host, and thereby,
    forwarded to a syslog server if configured. In addition the values of each entry
    can be used to create vROps metrics.
    Basic configurations options are stored in ./config.json file.
    
    NOTE:
        - requires module PowerCLI to be installed --> Install-Module -Name VMware.PowerCLI
        - requires module Posh-SSH to be installed --> Install-Module -Name Posh-SSH
        - requires encrypted credentials for every host (vCenter, ESXi, vROps) to be stored
          in a file and copied to script directory:
            New-VICredentialStoreItem -Host ESX1 –User root –Password SecretPass
            New-VICredentialStoreItem -Host ESX2 –User root –Password SecretPass
            New-VICredentialStoreItem -Host VC –User user –Password SecretPass
            New-VICredentialStoreItem -Host vROps –User admin –Password SecretPass
            Copy $env:APPDATA\VMware\credstore\vicredentials.xml path\to\copy\vicredentials.xml
        - requires a config.json with this example content:
            {
              "credentialLoc": "path\\to\\vicredentials.xml",
              "vCenterHost": "VC",
              "shellScriptLoc": "path\\to\\get-dfwhostmetrics.sh",
              "exclusionTag": "TagName",
              "postToVrops": "true",
              "vropsHost": "vROps",
              "vropsAuthSource": "Local"
            }
        - requires get-dfwhostmetrics.sh shell script to be executet locally on every
          ESXi host

.EXAMPLE
    Write-DfwMetricsToLogOps -configLoc <path\to\config.json>

.NOTES
    Author: kschwender@vmware.com
    Last Edit: 9/16/22
    Version 2.0 - In addition to write DFW metrics to syslog it allows to write it to vROps

#>

param (
    <#
    .PARAMETER configLoc
        Location of the configuration JSON

    #>

    [Parameter(Mandatory = $true)]
    [string]$configLoc
)

# Function to convert Date/Time to Unix Time (Epoch)
function ConvertTo-UnixTimestamp {
    $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0              
    $input | ForEach-Object {                       
        $result = [math]::truncate($_.ToUniversalTime().Subtract($epoch).TotalMilliSeconds)
        return $result
    }            
}

#Function to get vROps auth token
function Get-vROpsAuthToken {
    param (
        [Parameter(Mandatory)]
        [string] $server,

        [Parameter(Mandatory)]
        [string]$user,

        [Parameter(Mandatory)]
        [string]$authSource,

        [Parameter(Mandatory)]
        [string]$password
    )

    # Generate login JSON structure to get vROps auth token
    $loginBody = @{
        username = $user
        authSource = $authSource
        password = $password
        others = ''
        otherAttributes = ''
    } | ConvertTo-Json

    # Get vROps auth token
    $response = Invoke-RestMethod -Uri "https://$server/suite-api/api/auth/token/acquire" -Method POST -ContentType 'application/json' -Body $loginBody

    # Clear unsecure variables and return auth token
    Remove-Variable -Name password -Force -Confirm:$false
    Remove-Variable -Name loginBody -Force -Confirm:$false
    return $response.'auth-token'.token
}

# Function to query vROps Object ID
function Get-vROpsObjectId {
    param (
        [Parameter(Mandatory)]
        [string]$server,

        [Parameter(Mandatory)]
        [string]$objectName,

        [Parameter(Mandatory)]
        [string]$objectType,

        [Parameter(Mandatory)]
        [string]$authToken
    )

    $response = Invoke-RestMethod -Uri "https://$server/suite-api/api/resources?name=$objectName&resourceKind=$objectType&_no_links=true" -Method GET -ContentType 'application/json' -Headers @{'Authorization'='vRealizeOpsToken '+$authToken;'accept'='application/json'}
    return $response.ResourceList.Identifier
}

# Function to generate vROps metric JSON
function New-vROpsMetricJson {
    param (
        [string]$metricType = 'data',
        
        [string]$metricCat = 'Custom Metrics',

        [string]$metricSubCat = 'NSX DFW',

        [Parameter(Mandatory)]
        [string]$metricName,

        [Parameter(Mandatory)]
        [int64]$time,

        [Parameter(Mandatory)]
        $data
    )
    
    # Generate vROps metric JSON structure
    $metricJson = [PSCustomObject]@{
        'stat-content' = @(
            @{
            statKey = $metricCat+'|'+$metricSubCat+'|'+$metricName
            timestamps = @( $time )
            $metricType = @( $data )
            others = @( '' )
            otherAttributes = @{ }
            }
        )
    } | ConvertTo-Json -Depth 3
    return $metricJson
}

# Function to post vROps Metric
function Write-vROpsMetric {
    param (
        [Parameter(Mandatory)]
        [string]$server,

        [Parameter(Mandatory)]
        [string]$objectId,

        [Parameter(Mandatory)]
        [string]$authToken,

        [Parameter(Mandatory)]
        [string]$body
    )
    
    $response = Invoke-RestMethod -Uri "https://$server/suite-api/api/resources/$objectId/stats" -Method POST -ContentType 'application/json' -Headers @{'Authorization'='vRealizeOpsToken '+$authToken;'accept'='application/json'} -Body $body
}

# Skip SSL verification
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

# Read all information to variables
Write-Host "$(Get-Date): Reading config files"
if (-not (Test-Path $configLoc -PathType Leaf)) { throw "The file $configLoc does not exist." }
$config = Get-Content $configLoc | ConvertFrom-Json
if (-not (Test-Path $config.shellScriptLoc -PathType Leaf)) { throw "The file $config.shellScriptLoc does not exist." }
if (-not (Test-Path $config.credentialLoc -PathType Leaf)) { throw "The file $config.credentialLoc does not exist." }
$shellScript = (Get-Content $config.shellScriptLoc | Select-String -Pattern '^#|^\s*#|^\s*$' -NotMatch) -join '; ' -replace '\t', '' -replace 'do;', 'do' -replace 'then;', 'then'

# Connect to vCenter Server
Write-Host "$(Get-Date): Connecting to vCenter Server $($config.vCenterHost)"
$credentials = Get-VICredentialStoreItem -Host $config.vCenterHost -File $config.credentialLoc
Connect-VIServer -Server $credentials.Host -User $credentials.User -Password $credentials.Password -ErrorAction SilentlyContinue | Out-Null

# If enabled, get vROps auth token
if ($config.postToVrops -eq $true) {
    
    # Get vROps auth token
    Write-Host "$(Get-Date): Get vROps auth token from server $($config.vropsHost)"
    $credentials = Get-VICredentialStoreItem -Host $config.vropsHost -File $config.credentialLoc
    $vropsAuthToken = Get-vROpsAuthToken -server $credentials.Host -user $credentials.User -authSource $config.vropsAuthSource -password $credentials.Password
}

# Get all hosts from vCenter server and loop through
Get-VMHost | ForEach-Object -Process {
    
    # Check if host is connected and no exclustionTag is set
    Write-Host "$(Get-Date): Check if ESXi host $($_.Name) is connected and not excluded"
    if ($_.ConnectionState -eq 'Connected' -and ((Get-TagAssignment -Entity $_.Parent.Name).Tag.Name -ne $config.exclusionTag -or (Get-TagAssignment -Entity $_).Tag.Name -ne $config.exclusionTag)) {
        
        Write-Host "$(Get-Date): Proceed with ESXi host $($_.Name)"
        
        # Check if SSH is running, otherwise start SSH
        $sshRunning = (Get-VMHostService -VMHost $_).where({$_.Key -eq 'TSM-SSH'}).Running
        if (-not ($sshRunning)) {
            Write-Host "$(Get-Date): Starting SSH service on ESXi host $($_.Name)"
            Start-VMHostService -HostService (Get-VMHostService -VMHost $_.Name).where({$_.Key -eq 'TSM-SSH'}) -Confirm:$false | Out-Null
        }

        # Create SSH session to host and run commands which write DFW metrics to Syslog
        $credentials = Get-VICredentialStoreItem -Host $_.Name -File $config.credentialLoc
        $esxiCred = New-Object System.Management.Automation.PSCredential($credentials.User,($credentials.Password | ConvertTo-SecureString -AsPlainText -Force))
        Write-Host "$(Get-Date): Starting SSH sesstion to ESXi host $($_.Name)"
        $ssh = New-SSHSession -ComputerName $_.Name -Credential $esxiCred -AcceptKey -Force -WarningAction SilentlyContinue
        Write-Host "$(Get-Date): Running bash script on ESXi host $($_.Name) and write DFW metrics to syslog"
        $sshOut = Invoke-SSHCommand -SessionId $ssh.SessionId -Command $shellScript -ErrorAction Stop
        Write-Host "$(Get-Date): Closing SSH session to ESXi host $($_.Name)"
        Remove-SSHSession -SessionId $ssh.SessionId -InformationAction SilentlyContinue
        
        # Stop SSH if it was stopped before
        if (-not ($sshRunning)) {
            Write-Host "$(Get-Date): Stoping SSH service on ESXi host $($_.Name)"
            Stop-VMHostService -HostService (Get-VMHostService -VMHost $_.Name).where({$_.Key -eq 'TSM-SSH'}) -Confirm:$false | Out-Null
        }

        # If enabled, loop through SSH session output and post values as metrics to appropriate objects in vROps
        if ($config.postToVrops -eq $true) {
            
            Write-Host "$(Get-Date): Proceed with writing vROps metrics to server $($config.vropsHost)"

            # Process DFW rules per vNic and ESXi host
            $dfwSummary = $sshOut.Output -match 'dfw_vnic_name'
            [int64]$dfwRulesSum = 0
            if ($dfwSummary.Count -gt 0) {
                $dfwSummary | ForEach-Object {
                    
                    # Extract values from string
                    $vmName = $_.Split(',')[0].Split(':')[1].Split('.')[0]
                    $vNic = $_.Split(',')[0].Split(':')[1].Split('.')[1]
                    $dfwRules = [int64]$_.Split(',')[1].Split(':')[1]
                    $dfwRulesSum += $dfwRules

                    # Get vROps VM object, prepare metric and post it to vROps
                    Write-Host "$(Get-Date): Writing metrics for VM $vmName ($vNic), DFW rules applied value $dfwRules"
                    $objectId = Get-vROpsObjectId -server $config.vropsHost -objectName $vmName -objectType 'VirtualMachine' -authToken $vropsAuthToken
                    $unixTime = Get-Date | ConvertTo-UnixTimestamp
                    $dfwMetric = New-vROpsMetricJson -metricName $("DFW Rules applied on "+$vNic) -time $unixTime -data $dfwRules
                    Write-vROpsMetric -server $config.vropsHost -objectId $objectId -authToken $vropsAuthToken -body $dfwMetric
                }

                # Get vROps host object, prepare metric and post it to vROps
                Write-Host "$(Get-Date): Writing metrics for ESXi host $($sshOut.Host), DFW rules applied value $dfwRulesSum"
                $objectId = Get-vROpsObjectId -server $config.vropsHost -objectName $sshOut.Host -objectType 'HostSystem' -authToken $vropsAuthToken
                $unixTime = Get-Date | ConvertTo-UnixTimestamp
                $dfwMetric = New-vROpsMetricJson -metricName 'Total DFW Rules applied' -time $unixTime -data $dfwRulesSum
                Write-vROpsMetric -server $config.vropsHost -objectId $objectId -authToken $vropsAuthToken -body $dfwMetric
            } else {

                Write-Host "$(Get-Date): No data written (no VMs running on ESXi host $($sshOut.Host) or no VMs have DFW rules applied)" -ForegroundColor Blue
            }

            # Process DFW heap size per ESXi host
            $dfwSummary = $sshOut.Output -match 'dfw_heap_module_name'
            if ($dfwSummary.Count -gt 0) {
                $dfwSummary | ForEach-Object {
                    
                    # Extract values from string
                    $heapName = $_.Split(',')[0].Split(':')[1]
                    $heapUsage = [int64]$_.Split(',')[1].Split(':')[1]
                    
                    # Get vROps host object, prepare metric and post it to vROps
                    Write-Host "$(Get-Date): Writing metrics for ESXi host $($sshOut.Host), DFW heap mudule $heapName and value $heapUsage"
                    $objectId = Get-vROpsObjectId -server $config.vropsHost -objectName $sshOut.Host -objectType 'HostSystem' -authToken $vropsAuthToken
                    $unixTime = Get-Date | ConvertTo-UnixTimestamp
                    $dfwMetric = New-vROpsMetricJson -metricName $('DFW Heap Usage of '+$heapName+' (%)') -time $unixTime -data $heapUsage
                    Write-vROpsMetric -server $config.vropsHost -objectId $objectId -authToken $vropsAuthToken -body $dfwMetric
                }
            } else {

                Write-Host "$(Get-Date): No data written (ESXi host $($sshOut.Host) has no NSX modules installed)" -ForegroundColor Blue
            }
        }

        # Clear sshOut variable for next run
        $sshOut = [PSCustomObject]@{}
    } else {
    
        Write-Host "$(Get-Date): ESXi host $($_.Name) is neither in maintenance mode or not connected to vCenter Server $($config.vCenterHost) or excluded from being processed" -ForegroundColor Yellow
    }
}

# Disconnect from vCenter Server and clear credentials
Write-Host "$(Get-Date): Disconnecting from vCenter Server $($config.vCenterHost)"
Disconnect-VIServer -Force -Confirm:$false
Remove-Variable -Name credentials -Force -Confirm:$false
Remove-Variable -Name vropsAuthToken -Force -Confirm:$false
