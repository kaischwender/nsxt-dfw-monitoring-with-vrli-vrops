# nsxt-dfw-monitoring-with-vrli-vrops
Purpose of this is for monitoring and alerting NSX-T distributed firewall (DFW) VM and metrics with vRealize Log Insight (vRLI) and vRealize Operations
(vROps). This includes DFW rules applied per virtual NIC, DFW rules applied per Host and DFW heap usage per host.

## Technologies
Write-DfwMetricsToLogOps.ps1 was tested with
  - PowerShell 5.1
  - Posh-SSH 2.3.0
  - VMware.PowerCLI 12.3

get-dfwhostmetrics.sh was tested with
  - ESXi 6.7 and above (busybox)
  
An SSH session is established between the host running the PowerShell script and every ESXi host. Make sure TCP 22 is allowed by your firewalls.

## Setup
1. Install required modules
  - Install-Module -Name Posh-SSH
  - Install-Module -Name VMware.PowerCLI
2. Create encrypted credentials for every host (vCenter, ESXi and vROps) and copy the credential file to the script location by running
  - New-VICredentialStoreItem -Host ESX1 –User root –Password SecretPass
  - New-VICredentialStoreItem -Host ESX2 –User root –Password SecretPass
  - New-VICredentialStoreItem -Host VC –User user –Password SecretPass
  - New-VICredentialStoreItem -Host vROps –User admin –Password SecretPass
  - Copy $env:APPDATA\VMware\credstore\vicredentials.xml path\to\copy\vicredentials.xml
3. Modify confi.json with your infrastructure details
4. Make sure get-sfwhostmetrics.sh is available at the script location
5. Run command "Write-DfwMetricsToLogOps.ps1 -configLoc ./config.json"
6. Optional: Schedule this script to run on regular basis

Voilat, DFW VM and Host metrics are written to the syslog of every host, and thereby, forwarded if a syslog server if configured. In addition, all the
metrics have been written to the appropriate vROps objects (enabled by default in config.json).
