#!/bin/bash -x
cd /home/dscao/works/pxed
nohup ./pxe_proxy -v -c pxed.conf > pxe_err.log 2>&1 &
sleep 3
exit 0
