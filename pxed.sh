#!/bin/bash -x
#
function kill_proxy()
{
	sudo killall pxe_proxy
}
#
trap kill_proxy SIGINT SIGTERM
#
cd /home/dscao/works/pxed
sudo systemctl start apache2
sudo systemctl start tftpd-hpa
#sudo ./pxe_proxy -v -c pxed.conf > pxe_err.log 2>&1  &
sudo ./pxe_proxy -v -c pxed.conf &
wait
sudo systemctl stop tftpd-hpa
sudo systemctl stop apache2
