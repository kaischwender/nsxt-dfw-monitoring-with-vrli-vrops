#!/bin/sh

# Author: kschwender@vmware.com
# Last Edit: 9/16/22
# Version 2.0 - Echo values allows further parsing in PowerShell (invoked SSH script)

# General variables
IFS=$'\n'
hostRules=0

# Looping throuth summarize-dvfilter command, extracting all DFW rule counts per VM NIC, summarize counts per host and send it all to syslog
for filter in $(summarize-dvfilter | grep -E '\.eth[0-9]{1,2}|sfw.2$' | awk 'BEGIN{ORS="";} {gsub(/^\sport\s[0-9]{8,9}\s/,""); gsub(/\s{3}name:\s/,";"); gsub(/sfw.2$/,"sfw.2\n"); print}')
do
	vNicName=$(echo $filter | awk -F';' '{print $1}')
	vNicFilterName=$(echo $filter | awk -F';' '{print $2}')
	vNicRules=$(vsipioctl getrules -f $vNicFilterName | grep -w rule -c)
	hostRules=$(($hostRules+$vNicRules))
	if [ $vNicRules -gt 0 ]
	then
		logger -t hostd "dfw_vnic_name: $vNicName, dfw_vnic_rules: $vNicRules"
        echo "dfw_vnic_name:$vNicName, dfw_vnic_rules:$vNicRules"
	fi
done
logger -t hostd "dfw_host_rules: $hostRules"

# Looping through NSX thresholds, extracting the heap size usage and send it to syslog 
for heap in $(nsxcli -c get firewall thresholds | grep -E '^\s[0-9].*')
do
	heapModule=$(echo $heap | awk '{print $2}')
	heapUsage=$(echo $heap | awk '{print $5}')
	logger -t hostd "dfw_heap_module_name: $heapModule, dfw_heap_module_usage: $heapUsage"
    echo "dfw_heap_module_name:$heapModule, dfw_heap_module_usage:$heapUsage"
done