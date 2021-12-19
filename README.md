# IK2206

JDK 17
java ForwardServer --handshakehost=localhost  --handshakeport=0123 --usercert=server.pem --cacert=ca.pem --key=server-private.der

java ForwardClient --proxyport=2345  --handshakeport=0123 --usercert=client.pem --cacert=ca.pem --key=client-private.der --targetport=9876 --handshakehost=localhost --targethost=localhost

ncat -l 9876
ncat localhost 2345

OK FINE :)
