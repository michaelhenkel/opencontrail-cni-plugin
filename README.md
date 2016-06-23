```
git clone https://github.com/michaelhenkel/cni
git clone https://github.com/michaelhenkel/opencontrail-cni-plugin
cp -r ~/opencontrail-cni-plugin/opencontrail ~/cni/plugins/main
cp -r ~/opencontrail-cni-plugin/opencontrail-ipam ~/cni/plugins/ipam
add-apt-repository ppa:ubuntu-lxc/lxd-stable
apt-get update
apt-get install -y golang jq
export GOPATH=/usr/lib/go/
export CNI_PATH=~/cni/bin
cd CNI_PATH
go get github.com/michaelhenkel/contrail-go-api
go get github.com/satori/go.uuid
./build
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-opencontrail.conf <<EOF
{
    "name": "vnx",
    "type": "opencontrail",
    "api_server": "10.87.64.34",
    "api_port": 8082,
    "auth_url": "http://10.87.64.34:35357/v2.0/",
    "tenant_name": "admin",
    "admin_user": "admin",
    "admin_password": "contrail123",
    "admin_token": "",
    "mtu": 1492,
    "ipam": {
        "type": "opencontrail-ipam",
        "subnet": "10.22.0.0/24",
        "routes": [
            { "dst": "0.0.0.0/0" }
        ]
    }
}
EOF
bin/opencontrail-ipam &
ip netns add test
export CNI_COMMAND=ADD
export CNI_PATH=/root/cni/bin
export PATH=$CNI_PATH:$PATH
export CNI_CONTAINERID=test
export CNI_NETNS=/var/run/netns/test
export CNI_IFNAME=eth0
opencontrail < /etc/cni/net.d/10-opencontrail.conf
ip netns exec test ip addr sh
export CNI_COMMAND=ADD; opencontrail < /etc/cni/net.d/10-opencontrail.conf
export CNI_COMMAND=DEL; opencontrail < /etc/cni/net.d/10-opencontrail.conf
ip netns del test && ip netns add test
```
