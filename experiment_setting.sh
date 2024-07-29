#!bin/bash

interface_name='ens5'

sudo ifconfig $interface_name mtu 1500

sudo ifconfig $interface_name txqueuelen 10000

sudo ifconfig $interface_name | grep 'MTU:'

sudo ifconfig $interface_name | grep 'txqueuelen:' 

# sudo echo 0 > /sys/module/tcp_cubic/parameters/hystart

sudo sysctl -w net.ipv4.tcp_no_metrics_save=1

# sudo sysctl -w net.ipv4.tcp_retries2=2

sudo sysctl -w net.ipv4.tcp_wmem="16000000 16000000 256000000"
sudo sysctl -w net.ipv4.tcp_rmem="16000000 16000000 256000000"
sudo sysctl -w net.core.wmem_max="256000000"
sudo sysctl -w net.core.rmem_max="256000000"
sudo sysctl -w net.core.wmem_default="256000000"
sudo sysctl -w net.core.rmem_default="256000000"

