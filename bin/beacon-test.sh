if [ $# -lt 2 ]; then
	echo "syntax : beacon-test.sh <interface> <ap mac> [<bitmap>]"
	echo "sample : beacon-test.sh mon0 00:00:00:11:11:11"
	exit 1
fi
INTERFACE="$1"
AP_MAC="$2"

FILTER="wlan.addr==$AP_MAC && wlan.fc.type_subtype==8"
#FILTER+="!(radiotap.length==13)"
if [ $# -eq 3 ]; then
	FILTER+=" && ($3)"
fi

echo "FILTER="$FILTER
sudo tshark -i $INTERFACE -T fields -e frame.time_relative -e frame.time_delta_displayed -e radiotap.length -e wlan.seq -e wlan.fixed.timestamp -e wlan.tim.partial_virtual_bitmap -Y "$FILTER"
