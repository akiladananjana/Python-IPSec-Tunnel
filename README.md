# Python-IPSec-Tunnel

This is the basic implementation of the IPSec tunnel using Linux TUN/TAP interfaces and python RAW Sockets. This also includes the encryption part using AES algorithm.

## Requirements to run this Tunnel
* One Interface with Static IP configured
* interface should be active
* TUN interfaces
* Python 3.8.2 (tested)
* 2x Ubuntu 20.04 VM (tested)

# Basic Setup
For this tunnel program, I added two NICs to my Ubuntu box. One NIC is TUN interface that works as a virtual NIC and other one use to send and recv the actual tunnel traffic. The same program we run on both VMs. To execute the tunnel I added two Ubuntu 20.04 VMs into VMware workstation. They has following configs.

### Ubuntu VM 1
* Physical NIC IP : 192.168.1.10/24
* Logical NIC IP : 10.0.0.1/24

### Ubuntu VM 2
* Physical NIC IP : 192.168.1.20/24
* Logical NIC IP : 10.0.0.2/24

**Important:** The Physical NICs needs to have IP connectivity.

Use the following code for add the TUN interface into Ubuntu VM

```ip tuntap add dev asa0 mode tun``` </br>
```ip addr add 10.0.0.1/24 dev asa0```</br>
```ip link set dev asa0 up```</br>


# How this Basic IPSec Tunnel works?
Before execute the Python script, I generate a ping using Virtual NIC(asa0) on VM1 to VM2. Use the following command to generate the ping. </br></br>
```ping -I 10.0.0.1 10.0.0.2``` </br></br>
The ICMP packet is generated by asa0 Interface on VM1 and It has no route. I capture that packet using my python script and encrypt the packet with AES algorithm. Then I encapsulates the packet within new IP packet and send it to Physical NIC on VM2. When the packet arrives to VM2's physical NIC, It decrypt the packet and Write it into It's Virtual NIC(asa0). Then VM2's Virtual NIC reply to the ping, python program capture the packet and encrypt it. The whole IP conversation goes like that. Therefore vNICs have IP Connectivity because of the Python program. When the program terminates, the IP Connectivity also loss betweeen vNICs.

# Required Packages
* Pycryptodome : To encrypt the packets with AES algorithm. (pip3 install pycryptodome)
