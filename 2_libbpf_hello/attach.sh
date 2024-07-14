sudo ethtool -K eth0 lro off
sudo bpftool net attach xdp id 2021 dev eth0

