# OpenContrail CNI Plugin
This plugin provides overlay networking for CNI based infrastructures.    
It requires a working OpenContrail control plane and a host (aka Compute Node)    
with vrouter-agent and vrouter kernel module installed.    
The plugin has an IPAM and the plugin part. For now both must run on the Compute    
node.    
The IPAM plugin runs as a daemon in the background and is responsible for creating    
new virtual networks in case it doesn't exist and for assigning IP addresses and    
gateway information.    
The opencontrail plugin is an executable which creates virtual machine and virtual    
machine interface objects in the OpenContrail configuration database.    
It retrieves virtual network and ip instance information from the IPAM plugin.    
The virtual machine interface is referenced to the virtual machine and the     
ip instance to the virtual network and virtual machine interface.    

```
add-apt-repository ppa:ubuntu-lxc/lxd-stable
apt-get update
apt-get install -y golang jq
git clone https://github.com/michaelhenkel/cni
git clone https://github.com/michaelhenkel/opencontrail-cni-plugin
cp -r ~/opencontrail-cni-plugin/opencontrail ~/cni/plugins/main
#cp -r ~/opencontrail-cni-plugin/opencontrail-ipam ~/cni/plugins/ipam
export GOPATH=/usr/lib/go/
export CNI_PATH=~/cni/bin
cd ~/cni
go get github.com/michaelhenkel/contrail-go-api
go get github.com/satori/go.uuid
go get github.com/pborman/uuid
go get github.com/alexcesaro/log
./build
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-opencontrail-multi.conf <<EOF
{
    "networks": [
        {
            "name": "vnx",
            "type": "opencontrail",
            "mtu": 1492,
            "ipam": {
                "subnet": "10.22.0.0/24",
                "routes": [
                    { "dst": "0.0.0.0/0" }
                ]
            }
        },
        {
            "name": "vnx2",
            "type": "opencontrail",
            "mtu": 1492,
            "ipam": {
                "subnet": "10.23.0.0/24",
                "routes": [
                    { "dst": "0.0.0.0/0" }
                ]
            }
        }
    ]
}
EOF
export CNI_PATH=~/cni/bin
export PATH=$CNI_PATH:$PATH
export CNI_CONTAINERID=test
export CNI_NETNS=/var/run/netns/test
export CNI_IFNAME=eth0
export LOG_LEVEL=debug
#add namespace
ip netns add test
export CNI_COMMAND=ADD; opencontrail < /etc/cni/net.d/10-opencontrail-multi.conf
#check namespace
ip netns exec test ip addr sh
#delete namespace
export CNI_COMMAND=DEL; opencontrail < /etc/cni/net.d/10-opencontrail-multi.conf
ip netns del test
```
