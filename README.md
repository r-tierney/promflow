# Promflow - The Prometheus network flow monitoring tool

This script will capture packets on the interface you specify and count the number of bytes each IP is doing within the given monitor-subnets. \
These metrics are then exported as prometheus metrics via a http webserver listening on default port *:9088 \
To view these metrics: http://localhost:9088/metrics \
As these are count metrics you can apply a rate function on them to determine the bandwidth for each IP in your network.

Usage:
```
root@pop-os:~ ➜ ./promflow -h
Usage of ./promflow:
  -exclude-subnets string
    	Comma separated list of subnets to exclude from monitoring Example: 192.168.0.0/24,192.168.12.0/23 (default "255.255.255.250/32")
  -interface string
    	The interface to monitor for network traffic (default "eth0")
  -metrics-address string
    	Address to listen on for Prometheus metrics (default ":9088")
  -monitor-subnets string
    	Comma separated list of subnets to monitor Example: 192.168.0.0/24,192.168.12.0/23 (default "192.168.0.1/24")
```

Example:
> This example will export metrics for network traffic going to or from our LAN subnet 192.168.1.0/24 but will exclude any network traffic going to or from our VPN subnet 192.168.8.0/24
```
root@pop-os:~ ➜ ./promflow --interface="eth0" --monitor-subnets="192.168.1.0/24" --exclude-subnets="192.168.8.0/24" --metrics-address='192.168.0.1:9088'
```
To view the metrics: http://localhost:9088/metrics

Example metrics:
```
promflow_receive_bytes_total{ip="192.168.1.133"} 194179
promflow_receive_bytes_total{ip="192.168.1.5"} 6108
promflow_transmit_bytes_total{ip="192.168.1.1"} 354
promflow_transmit_bytes_total{ip="192.168.1.100"} 2544
promflow_transmit_bytes_total{ip="192.168.1.109"} 24427
promflow_transmit_bytes_total{ip="192.168.1.122"} 340
promflow_transmit_bytes_total{ip="192.168.1.133"} 181358
promflow_transmit_bytes_total{ip="192.168.1.5"} 9476
```

Grafana Example of how to get the top 5 highest bandwidth users; multiplying by 8 to convert from bytes to bits for mb/s
```
topk(5, sum(rate(promflow_receive_bytes_total{ip=~"192.168.0.*"}[30s])) by (ip)) * 8
topk(5, sum(rate(promflow_transmit_bytes_total{ip=~"192.168.0.*"}[30s])) by (ip)) * 8
```


To Build this script:
> This script will compile the Go source code for the operating system of your choice, simply update the `operating_system` variable within this build script before running. 
```
./build.sh
```

