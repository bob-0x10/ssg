if [ $# -ne 2 ]; then
	echo "syntax : station-test.sh <interface> <ap mac>"
	echo "sample : station-test.sh mon0 E4:F8:9C:67:E4:CC"
	exit 1
fi
INTERFACE="$1"
STA_MAC="$2"

sudo tcpdump -i $INTERFACE "ether src host $STA_MAC"
