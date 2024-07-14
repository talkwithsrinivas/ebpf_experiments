sudo bpftool net detach xdp dev eth0
sudo ethtool -K eth0 lro on
