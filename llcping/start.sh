#!/bin/sh
#
# Script to run various llcping tests for llc1 and llc2 sockets.
# Jay Schulist <jschlst@samba.org>
#

SERVER_MAC="00:90:27:18:0A:0D"
CLIENT0_MAC="00:03:47:9C:D6:AD"
CLIENT1_MAC="00:A0:24:01:D1:57"

case "$1" in
	llc1-echo-client0-test-null)
		./llcping ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc1-echo-client0-test-sap)
		./llcping -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc1-echo-client0-mac+sap-diff)
		./llcping -m -u -s 0x90 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
        ;;

	llc1-echo-client0-mac+sap)
		./llcping -m -u -s 0x88 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc1-echo-client0-any+sap)
		./llcping -u -s 0x88 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc1-echo-client1-mac+sap)
		./llcping -m -u -s 0x88 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
	;;

	llc1-echo-client1-any+sap)
		./llcping -u -s 0x88 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client0-mac+sap)
		./llcping -m -2 -u -s 0x88 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client0-mac+sap-flood)
		./llcping -f -m -2 -u -s 0x88 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
        ;;

	llc2-echo-client0-any+sap)
		./llcping -2 -u -s 0x88 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client0-mac+sap-nodata)
		./llcping -m -n -2 -u -s 0x88 -d 0x88 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client0-mac+sap1)
		./llcping -m -2 -u -s 0x50 -d 0x50 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client0-mac+sap1-diff)
		./llcping -m -2 -u -s 0x40 -d 0x50 ${CLIENT0_MAC} ${SERVER_MAC}
        ;;

	llc2-echo-client0-mac+sap1-srv)
		./llcping -m -2 -u -s 0x50 -d 0x50 ${SERVER_MAC} ${CLIENT0_MAC}
        ;;

	llc2-echo-client1-mac+sap1-srv)
                ./llcping -m -2 -u -s 0x52 -d 0x50 ${SERVER_MAC} ${CLIENT1_MAC}
        ;;

	llc2-echo-client0-mac+sap2)
		./llcping -m -2 -u -s 0x52 -d 0x52 ${CLIENT0_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client1-mac+sap-flood)
                ./llcping -f -m -2 -u -s 0x88 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
        ;;

	llc2-echo-client1-mac+ssap)
		./llcping -m -2 -u -s 0x40 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client1-mac+sap)
		./llcping -m -2 -u -s 0x88 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client1-any+sap)
		./llcping -2 -u -s 0x88 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client1-mac+sap-nodata)
		./llcping -n -m -2 -u -s 0x88 -d 0x88 ${CLIENT1_MAC} ${SERVER_MAC}
	;;

	llc2-echo-client1-mac+sap1)
                ./llcping -m -2 -u -s 0x50 -d 0x50 ${CLIENT1_MAC} ${SERVER_MAC}
        ;;
        
        llc2-echo-client1-mac+sap2)
                ./llcping -m -2 -u -s 0x52 -d 0x52 ${CLIENT1_MAC} ${SERVER_MAC}
        ;;

	llc1-echo-server-any+sap)
		./llcpingd ${SERVER_MAC}
	;;

	llc2-echo-server-any+sap)
		./llcpingd -2 ${SERVER_MAC}
	;;

	llc2-echo-server-loop-any+sap)
		./llcpingd2 -2 ${SERVER_MAC}
	;;

	llc2-echo-server-loop-any+sap1)
		./llcpingd2 -2 -s 0x50 ${SERVER_MAC}
	;;

	llc2-echo-server-loop-mac+sap1)
		./llcpingd2 -m -2 -s 0x50 ${SERVER_MAC}
        ;;

	llc2-echo-server-loop-mac+sap1-ca0)
		./llcpingd2 -m -2 -s 0x50 ${CLIENT0_MAC}
        ;;

	llc2-echo-server-loop-mac+sap1-ca1)
                ./llcpingd2 -m -2 -s 0x50 ${CLIENT1_MAC}
        ;;

	llc2-echo-server-loop-any+sap2)
		./llcpingd2 -2 -s 0x52 ${SERVER_MAC}
	;;

	llc2-echo-server-loop-mac+sap2)
		./llcpingd2 -m -2 -s 0x52 ${SERVER_MAC}
        ;;

	*)
	echo "Usage:"
	echo "	\`$0 llc1-echo-server\`, Start llc1 echo server."
	echo "	\`$0 llc2-echo-server\`, Start llc2 echo server."
	;;
esac
