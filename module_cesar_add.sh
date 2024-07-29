echo add César

sudo rmmod tcp_cesar.ko

sudo insmod tcp_cesar.ko && echo done

echo check César\(cesar\) is available

cat /proc/sys/net/ipv4/tcp_available_congestion_control