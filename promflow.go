package main

import (
    "strings"
    "log"
    "flag"
    "net"
    "net/http"
    "math"
    "time"
    "encoding/binary"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Create a map to store the bytes transmitted by each IP
var rx_stats map[string]float64 = make(map[string]float64)
var tx_stats map[string]float64 = make(map[string]float64)

// Prometheus specific globals config
const metricsNamespace string = "promflow"
var receiveByteCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
    Namespace: metricsNamespace,
    Name:      "receive_bytes_total",
    Help:      "Number of bytes received per IP",
}, []string{"ip"})

var transmitByteCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
    Namespace: metricsNamespace,
    Name:      "transmit_bytes_total",
    Help:      "Number of bytes sent per IP",
}, []string{"ip"})


// Return a set of all IPs in a CIDR network
func get_subnet_hosts(subnets string) map[string]struct{} {
    // 192.168.0.0/24,192.168.1.0/24 -> {'192.168.0.0', ..., '192.168.0.255', '192.168.1.0', ..., '192.168.1.255'}
    ips := map[string]struct{}{}
    for _, subnet := range strings.Split(subnets, ",") {
        // Convert string to IPNet struct
        _, ipv4Net, err := net.ParseCIDR(subnet)
        if err != nil { log.Fatal(err) }

        // Convert IPNet struct mask and address to uint32
        mask := binary.BigEndian.Uint32(ipv4Net.Mask)
        start := binary.BigEndian.Uint32(ipv4Net.IP)

        // This will give the final address in the range of IP addresses represented by the given CIDR block.
        finish := (start & mask) | (mask ^ 0xffffffff)

        // Loop through ip addresses as uint32 adding the string value to the ips slice
        for i := start; i <= finish; i++ {
             // convert back to net.IP
            ip := make(net.IP, 4)
            binary.BigEndian.PutUint32(ip, i)
            ips[ip.String()] = struct{}{}
        }
    }
    return ips
}


// Prevent float64 overflows by resetting all metrics at 90% of float64 max
func prevent_overflow(stats map[string]float64) {
    for _, bytes := range stats {
        if bytes >= math.MaxFloat64 * .9 || math.IsInf(bytes, 1) { // 90% of float64 or +inf
            log.Println("Resetting metrics to prevent float64 overflow")
            receiveByteCounter.Reset()
            transmitByteCounter.Reset()
            rx_stats = make(map[string]float64)
            tx_stats = make(map[string]float64)
        }
    }
}


func main() {
    // Parse flags Example: go run promflow.go --interface='enp88s0' --monitor-subnets='192.168.1.0/24'
    network_interface := flag.String("interface", "eth0", "The interface to monitor for network traffic")
    monitor_subnets := flag.String("monitor-subnets", "192.168.0.0/24", "Comma separated list of subnets to monitor Example: 192.168.0.0/24,192.168.1.0/24")
    exclude_subnets := flag.String("exclude-subnets", "255.255.255.250/32", "Comma separated list of subnets to exclude from monitoring Example: 192.168.14.0/24,192.168.8.0/24")
    metricsAddress := flag.String("metrics-address", ":9088", "Address to listen on for Prometheus metrics")
    flag.Parse()

    // Start the http server on another thread
    prometheus.MustRegister(receiveByteCounter, transmitByteCounter)
    go func() {
        http.Handle("/metrics", promhttp.Handler())
        log.Fatal(http.ListenAndServe(*metricsAddress, nil))
    }()

    // Convert subnets to a set of IP addresses 192.168.0.0/24 -> {'192.168.0.0', '192.168.0.1', ..., '192.168.0.255'}
    hosts_to_monitor := get_subnet_hosts(*monitor_subnets)
    excluded_hosts := get_subnet_hosts(*exclude_subnets)

    // Open the device for capturing ( device, snapshotLen, promisc, block until packet is received )
    handle, err := pcap.OpenLive(*network_interface, 1600, true, pcap.BlockForever)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    // Start capturing packets
    startTime := time.Now()
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Extract the IP layer
        ipLayer := packet.Layer(layers.LayerTypeIPv4)
        if ipLayer == nil { continue }
        ip, _ := ipLayer.(*layers.IPv4)

        // Extract the source and destination IP addresses
        src_ip := ip.SrcIP.String()
        dst_ip := ip.DstIP.String()

        // Increment the bytes transmitted for the source and destination IPs in the monitor-subnets but only if src and dst ip are not in the exclude-subnets set
        if _, ok := hosts_to_monitor[src_ip]; ok {
            if _, ok := excluded_hosts[src_ip]; !ok {
                transmitByteCounter.WithLabelValues(src_ip).Add(float64(ip.Length))
                tx_stats[src_ip] += float64(ip.Length)
            }
        }
        if _, ok := hosts_to_monitor[dst_ip]; ok {
            if _, ok := excluded_hosts[dst_ip]; !ok {
                receiveByteCounter.WithLabelValues(dst_ip).Add(float64(ip.Length))
                rx_stats[dst_ip] += float64(ip.Length)
            }
        }

        // Prevent float64 overflows by resetting all metrics at 90% of float64 max; check once per hour
        if time.Since(startTime) >= time.Second * 3600 {
            prevent_overflow(rx_stats)
            prevent_overflow(tx_stats)
            startTime = time.Now() // reset the timer
        }
    }
}
