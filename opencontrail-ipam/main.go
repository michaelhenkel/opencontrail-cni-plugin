//
// Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
//

package main

import (
	"github.com/Juniper/contrail-go-api"
	contrailtypes "github.com/Juniper/contrail-go-api/types"
        "github.com/Juniper/contrail-go-api/config"
        "github.com/containernetworking/cni/pkg/types"
        "github.com/containernetworking/cni/pkg/skel"
        "github.com/containernetworking/cni/pkg/ipam"
	"github.com/satori/go.uuid"
        "encoding/json"
	"flag"
	"fmt"
	"os"
        "net"
        "strconv"
)

var (
	oc_server string
	oc_port int
	os_auth_url string
	os_tenant_name string
	os_tenant_id string
	os_username string
	os_password string
	os_token string
        network_name string
)


type NetConf struct {
        types.NetConf
        ApiServer     string `json:"api_server"`
        ApiPort       int    `json:"api_port"`
        AuthUrl       string `json:"auth_url"`
        TenantName    string `json:"tenant_name"`
        AdminUser     string `json:"admin_user"`
        AdminPassword string `json:"admin_password"`
        AdminToken    string `json:"admin_token"`
        NetworkName   string `json:"name"`
}

func loadNetConf(bytes []byte) (*NetConf, error) {
        n := &NetConf{}
        if err := json.Unmarshal(bytes, n); err != nil {
                return nil, fmt.Errorf("failed to load netconf: %v", err)
        }
        return n, nil
}

func InitFlags(n *NetConf) {
	flag.StringVar(&oc_server, "server", n.ApiServer,
		"OpenContrail API server hostname or address")
	flag.IntVar(&oc_port, "port", n.ApiPort,
		"OpenContrail API server port")
	flag.StringVar(&os_tenant_name,
		"os-tenant-name", n.TenantName,
		"Authentication tenant name (Env: OS_TENANT_NAME)")
	flag.StringVar(&os_auth_url,
		"os-auth-url", n.AuthUrl,
		"Authentication URL (Env: OS_AUTH_URL)")
	flag.StringVar(&os_username,
		"os-username", n.AdminUser,
		"Authentication username (Env: OS_USERNAME)")
	flag.StringVar(&os_password,
		"os-password", n.AdminPassword,
		"Authentication password (Env: OS_PASSWORD)")
	flag.StringVar(&os_token,
		"os-token", n.AdminToken,
		"Authentication URL (Env: OS_TOKEN)")
	flag.StringVar(&network_name,
		"name", n.NetworkName,
		"network name")

}

func setupAuthKeystone(client *contrail.Client) {
	keystone := contrail.NewKeystoneClient(
		os_auth_url,
		os_tenant_name,
		os_username,
		os_password,
		os_token,
	)
	err := keystone.Authenticate()
        if err != nil {
                attempt := 0
                for i := 0; i < 3; i++ {
                        err := keystone.Authenticate()
                        if err == nil { break }
                        attempt += i
                }
                if err != nil {
                        fmt.Fprintln(os.Stderr, err)
                        os.Exit(1)
                }
        }
	client.SetAuthenticator(keystone)
}

func cmdAdd(args *skel.CmdArgs) error {
        n, err := loadNetConf(args.StdinData)
        InitFlags(n)
        flag.Parse()
        var dnsServer string
        var dnsServerList []string
        var defaultGateway string
        var ipPrefixLen int
        if err != nil {
                return err
        }
        client := contrail.NewClient(oc_server, oc_port)
        if len(os_auth_url) > 0 {
                setupAuthKeystone(client)
        }
        ipamConf, err := LoadIPAMConfig(args.StdinData, args.Args)
        vnUuid := networkCreate(client, ipamConf)
        vnObj, err := client.FindByUuid("virtual-network", vnUuid)
        vnObj2 := vnObj.(*contrailtypes.VirtualNetwork)
        ipamRefs, err := vnObj2.GetNetworkIpamRefs()
        for _, ref := range ipamRefs {
                attr := ref.Attr.(contrailtypes.VnSubnetsType)
                for _, ipamSubnet := range attr.IpamSubnets {
                        defaultGateway = ipamSubnet.DefaultGateway
                        dnsServer = ipamSubnet.DnsServerAddress
                        ipPrefixLen = ipamSubnet.Subnet.IpPrefixLen
                }
        }
        if err != nil {
                return err
        }
        instanceIpName := createInstanceIp(client, vnObj)
        instanceIpIObj, err := client.FindByName("instance-ip",instanceIpName)
        instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
        instanceipAddress :=instanceIpObj.GetInstanceIpAddress()
        netmask := net.CIDRMask(ipPrefixLen, 32)
        if err != nil {
                return err
        }
        ipConf := &types.IPConfig{
        	IP:      net.IPNet{IP: net.ParseIP(instanceipAddress), Mask: netmask},
                Gateway: net.ParseIP(defaultGateway),
        }
        dnsServerList = append(dnsServerList,dnsServer)

        dnsConf := types.DNS{
                Nameservers:	dnsServerList,
        }
	customAttribute := []types.Attribute{
		{"vnUuid",vnUuid},
		{"instanceIpName",instanceIpName},
	}

	customConf := &types.CUSTOM{
		CustomAttributes: customAttribute,
	}

        r := &types.Result{
                IP4: ipConf,
                DNS: dnsConf,
                CUSTOMATTR: customConf,
        }
        return r.Print()
}

func createInstanceIp(client *contrail.Client, vnObj contrail.IObject) (
        string){
	instanceIpUuid := uuid.NewV4().String()
	instanceIp := new(contrailtypes.InstanceIp)
        instanceIp.SetName(instanceIpUuid)
        instanceIp.AddVirtualNetwork(vnObj.(*contrailtypes.VirtualNetwork))
	client.Create(instanceIp)
        instanceIpIObj, err := client.FindByName("instance-ip",instanceIpUuid)
        if err != nil || instanceIpIObj == nil{
        	fmt.Fprintln(os.Stderr, err)
                os.Exit(1)
        }
	instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
        instanceIpObj.ClearVirtualNetwork()
        return instanceIpUuid
}

func networkCreate(client *contrail.Client, ipam *IPAMConfig)(
	string) {
        var parent_id string
        var err error
        var vnUuid string
        parent_id, err = config.GetProjectId(
                         client, os_tenant_name, "")
        if err != nil {
                fmt.Fprintln(os.Stderr, err)
                os.Exit(1)
        }
        networkList, err := config.NetworkList(client, parent_id, false)
        if err != nil {
                fmt.Fprint(os.Stderr, err)
                os.Exit(1)
        }
        for _, n := range networkList {
            if n.Name == ipam.Name {
                vnUuid := n.Uuid
                return vnUuid 
            }
        }
        fmt.Fprintln(os.Stderr, "network doesn't exist")
        subnet := net.IP(ipam.Subnet.IP).String()
        netmask := net.IP(ipam.Subnet.Mask).String()
        subnetSize, bits := net.IPMask(ipam.Subnet.Mask).Size()
        fmt.Fprintln(os.Stderr, subnetSize, bits)
        fmt.Fprintln(os.Stderr, network_name)
        fmt.Fprintln(os.Stderr, subnet)
        fmt.Fprintln(os.Stderr, netmask)
        parent_id, err = config.GetProjectId(
            client, os_tenant_name, "")
        fmt.Fprint(os.Stderr, parent_id)
        if err != nil {
            fmt.Fprint(os.Stderr, err)
            os.Exit(1)
        }
        vnUuid, err = config.CreateNetworkWithSubnet(client, parent_id, 
		network_name, subnet + "/" + strconv.Itoa(subnetSize))
	if err != nil {
            fmt.Fprint(os.Stderr, err)
            os.Exit(1)
        } 
        return vnUuid

}

func cmdDel(args *skel.CmdArgs) error {
        n, err := loadNetConf(args.StdinData)
        if err != nil {
                return err
        }
        ipam.ExecDel(n.IPAM.Type, args.StdinData)
        return nil
}

func main() {
        skel.PluginMain(cmdAdd, cmdDel)
}
