#!/bin/bash -x
#
function kill_proxy()
{
	sudo killall pxe_proxy
}
#
trap kill_proxy SIGINT SIGTERM
#
ipaddr=$(ip addr show dev eno1 | fgrep "inet " | awk '{print $2}')
[ -z "$ipaddr" ] && echo "eno1 has no ip" && exit 1
ipaddr=${ipaddr%/*}
sed -i -e "s#[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*#$ipaddr#" \
        /var/www/html/lenvdi/preseed-net.cfg
sed -i -e "s#[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*#$ipaddr#" \
        /var/svr/tftp/debian-installer/amd64/pxelinux.cfg/default
#
cd /home/dscao/works/pxed
sudo systemctl start apache2
sudo systemctl start tftpd-hpa
#sudo ./pxe_proxy -v -c pxed.conf > pxe_err.log 2>&1  &
sudo ./pxe_proxy -v -c pxed.conf &
sleep 3
wait
sudo systemctl stop tftpd-hpa
sudo systemctl stop apache2
