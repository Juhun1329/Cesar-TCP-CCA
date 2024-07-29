#!bin/bash

line_p=0
su=0
alpha=2
beta=5
gamma=8

if lsmod | grep tcp_cesar; then
	echo $mode > /sys/module/tcp_cesar/parameters/cesar_mode_outside
    echo "mode         "$(cat /sys/module/tcp_cesar/parameters/cesar_mode_outside)

	echo $su > /sys/module/tcp_cesar/parameters/cesar_scheduling_unit
    echo "su           "$(cat /sys/module/tcp_cesar/parameters/cesar_scheduling_unit)

	echo $alpha > /sys/module/tcp_cesar/parameters/cesar_alpha
    echo "alpha        "$(cat /sys/module/tcp_cesar/parameters/cesar_alpha)

	echo $beta > /sys/module/tcp_cesar/parameters/cesar_beta
    echo "beta         "$(cat /sys/module/tcp_cesar/parameters/cesar_beta)

	echo $gamma > /sys/module/tcp_cesar/parameters/cesar_gamma
    echo "gamma        "$(cat /sys/module/tcp_cesar/parameters/cesar_gamma)
else
    echo "add cesar module first"
    exit 1
fi


