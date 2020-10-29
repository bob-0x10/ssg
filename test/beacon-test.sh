if [ $# -ne 2 ]; then
	echo "syntax : beacon-test.sh <interface> <ap mac>"
	echo "sample : beacon-test.sh mon0 90:9F:33:D9:A0:E0"
	exit 1
fi
INTERFACE="$1"
AP_MAC="$2"

sudo tshark -i $INTERFACE -T fields -e frame.time_relative -e frame.time_delta_displayed -e radiotap.length -e wlan.seq -e wlan.fixed.timestamp -e wlan.tim.partial_virtual_bitmap -Y "wlan.addr==$AP_MAC && wlan.fc.type_subtype==8"
