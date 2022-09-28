# nsxt-dfw-monitoring-with-vrli-vrops
Purpose of this is for monitoring and alerting NSX-T distributed firewall (DFW) VM and metrics with vRealize Log Insight (vRLI) and vRealize Operations
(vROps). This includes DFW rules applied per virtual NIC, DFW rules applied per Host and DFW heap usage per host.

![Alt text](https://github.com/kaischwender/nsxt-dfw-monitoring-with-vrli-vrops/blob/main/vRLI/vRLI-Dashboard.jpg?raw=true "vRLI Dashboard")

![Alt text](https://github.com/kaischwender/nsxt-dfw-monitoring-with-vrli-vrops/blob/main/vROps/vROps-Dashboard.jpg?raw=true "vROps Dashboard")

## Technologies
Write-DfwMetricsToLogOps.ps1 was tested with
  - PowerShell 5.1
  - Posh-SSH 2.3.0
  - VMware.PowerCLI 12.3

get-dfwhostmetrics.sh was tested with
  - ESXi 6.7 and above (busybox)
  
Please make sure HTTPS, TCP 443 (scripting host to vCenter/vROps) and SSH, TCP 22 (scripting host to ESXi) are allowed by your firewalls.

## Installation
1. Copy the files (Write-DfwMetricsToLogOps.ps1, config.json and get-sfwhostmetrics.sh) to the desired location
2. Install required modules
  - Install-Module -Name Posh-SSH
  - Install-Module -Name VMware.PowerCLI
3. Create encrypted credentials for every host (vCenter, ESXi and vROps) and copy the credential file to the script location by running
  - New-VICredentialStoreItem -Host [ESX1] –User [root] –Password [SecretPass]
  - New-VICredentialStoreItem -Host [ESX2] –User [root] –Password [SecretPass]
  - New-VICredentialStoreItem -Host [VC] –User [user] –Password [SecretPass]
  - New-VICredentialStoreItem -Host [vROps] –User [admin] –Password [SecretPass]
  - Copy $env:APPDATA\VMware\credstore\vicredentials.xml [path\to\copy\vicredentials.xml]
4. Modify "confi.json" and change it to your infrastructure details

## Usage
Run command within a PowerShell session "Write-DfwMetricsToLogOps.ps1 -configLoc ./config.json" and the PowerShell script will do its part.
- Syslog: DFW metrics are written to the syslog of every host and forwarded to a syslog destination, for example vRLI, if configured.
- vROps: DFW metrics are written to its appropriate object, which is either a VM or a host, if enabled in "config.json". There are several new DFW metrics created, which are
  - VM|Custom Metric|NSX DFW|DFW Rules applied on eth[0-9]
  - HostSystem|Custom Metric|NSX DFW|Total DFW Rules applied
  - HostSystem|Custom Metric|NSX DFW|DFW Heap Usage of [moduleName] (%)
  
In addition, there are some vRLI und vROps example dashboards and alerts available within the appropriate folders.
