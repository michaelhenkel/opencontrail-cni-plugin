//
// Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
//

package main

import (
	"github.com/michaelhenkel/contrail-go-api"
	contrailconfig "github.com/michaelhenkel/contrail-go-api/config"
        contrailtypes "github.com/michaelhenkel/contrail-go-api/types"
        "github.com/containernetworking/cni/pkg/types"
        "github.com/containernetworking/cni/pkg/skel"
        "github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/vishvananda/netlink"
	"github.com/satori/go.uuid"
        "encoding/json"
        "runtime"
	"flag"
	"fmt"
	"os"
        "net"
        "strings"
        "strconv"
)

type ExecFunc func(client *contrail.Client, flagSet *flag.FlagSet)

type CliCommand struct {
	flagSet *flag.FlagSet
	exec ExecFunc
}

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

	commandMap map[string]CliCommand = make(map[string]CliCommand, 0)
)

func RegisterCliCommand(name string, flagSet *flag.FlagSet, exec ExecFunc) {
	commandMap[name] = CliCommand{flagSet, exec}
}

type IPAMConfig struct {
        Name       string
        Type       string        `json:"type"`
        RangeStart net.IP        `json:"rangeStart"`
        RangeEnd   net.IP        `json:"rangeEnd"`
        Subnet     types.IPNet   `json:"subnet"`
        Gateway    net.IP        `json:"gateway"`
        Routes     []types.Route `json:"routes"`
        Args       *IPAMArgs     `json:"-"`
}

type IPAMArgs struct {
        types.CommonArgs
        IP net.IP `json:"ip,omitempty"`
}

type Net struct {
        Name string      `json:"name"`
        IPAM *IPAMConfig `json:"ipam"`
}

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
	MTU           int    `json:"mtu"`
        Ipam	      IPAMConfig `json:"ipam"`
}

type MultiConf struct {
	Networks	[]NetConf `json:"networks"`
}

func loadMultiConf(bytes []byte) (*MultiConf, error) {
	netConfList := &MultiConf{}
        json.Unmarshal(bytes, netConfList)
        for _, netConf := range netConfList.Networks {
		conf := netConf
                fmt.Print("netconf: ", conf.NetworkName)
	}
        return netConfList, nil
}

func loadNetConf(bytes []byte) (*NetConf, error) {
        n := &NetConf{}
        if err := json.Unmarshal(bytes, n); err != nil {
                return nil, fmt.Errorf("failed to load netconf: %v", err)
        }
        return n, nil
}

func init() {
    // this ensures that main runs only on main thread (thread group leader).
    // since namespace ops (unshare, setns) are done for a single thread, we
    // must ensure that the goroutine does not jump from OS thread to thread
    runtime.LockOSThread()
}

/*
func InitFlags(n *NetConf) {
        if n.ApiServer == "" {
        	n.ApiServer = os.Getenv("API_SERVER_IP")
        }
        if n.ApiPort == 0 {
        	n.ApiPort, _ = strconv.Atoi(os.Getenv("API_SERVER_PORT"))
	}
	if n.TenantName == "" {
		n.TenantName = os.Getenv("OS_TENANT_NAME")
	}
	if n.AuthUrl == "" {
		n.AuthUrl = os.Getenv("OS_AUTH_URL")
	}
	if n.AdminUser == "" {
		n.AdminUser = os.Getenv("OS_USERNAME")
	}
	if n.AdminPassword == "" {
		n.AdminPassword = os.Getenv("OS_PASSWORD")
	}
        n.AdminToken = ""
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
*/
func InitFlags() {

        api_port, _ := strconv.Atoi(os.Getenv("API_SERVER_PORT"))
        flag.StringVar(&oc_server, "server", os.Getenv("API_SERVER_IP"),
                "OpenContrail API server hostname or address")
        flag.IntVar(&oc_port, "port", api_port,
                "OpenContrail API server port")
        flag.StringVar(&os_tenant_name,
                "os-tenant-name", os.Getenv("OS_TENANT_NAME"),
                "Authentication tenant name (Env: OS_TENANT_NAME)")
        flag.StringVar(&os_auth_url,
                "os-auth-url", os.Getenv("OS_AUTH_URL"),
                "Authentication URL (Env: OS_AUTH_URL)")
        flag.StringVar(&os_username,
                "os-username", os.Getenv("OS_USERNAME"),
                "Authentication username (Env: OS_USERNAME)")
        flag.StringVar(&os_password,
                "os-password", os.Getenv("OS_PASSWORD"),
                "Authentication password (Env: OS_PASSWORD)")
        flag.StringVar(&os_token,
                "os-token", os.Getenv("OS_TOKEN"),
                "Authentication URL (Env: OS_TOKEN)")
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


func setupVeth(netns ns.NetNS, ifName string, mtu int) (net.HardwareAddr, string, error) {
    var hostVethName string
    var vethMac net.HardwareAddr

    err := netns.Do(func(hostNS ns.NetNS) error  {
        hostVeth, _, err := ip.SetupVeth(ifName, mtu, hostNS)
        if err != nil {
            return err
        }

        hostVethName = hostVeth.Attrs().Name
        return nil
    })
    if err != nil {
        return vethMac,hostVethName, err
    }
    //ns = netns.Get(netns)
    netns.Do(func(netns ns.NetNS) error  {
    	contVeth, _ := netlink.LinkByName(ifName)
        vethMac = contVeth.Attrs().HardwareAddr
        return err
    })

    return vethMac, hostVethName, nil
}

func cmdAdd(args *skel.CmdArgs) error {
        // create netnms
       	InitFlags()
       	flag.Parse()
       	netns, err := ns.GetNS(args.Netns)
        if err != nil {
                fmt.Fprintln(os.Stderr, err)
                os.Exit(1)
        }
        containerName := args.ContainerID
        if err != nil {
                return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
        }
        defer netns.Close()
        vethIntNumber := 0
        netConfList, _ := loadMultiConf(args.StdinData)
        for _, netConf := range netConfList.Networks {
                fmt.Print("netconf: ", netConf.NetworkName)
                vethInt := "eth" + strconv.Itoa(vethIntNumber)
                vethIntNumber = vethIntNumber + 1
                fmt.Print("vethInt: ", vethInt)
        	if err != nil {
        		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
    		}
                netConf.Ipam.Name = netConf.NetworkName
                fmt.Print("ipamConf: ", netConf.Ipam)
		vethMac, hostVethName, err := setupVeth(netns, vethInt, netConf.MTU)
        	//os.Exit(1)
        	client := contrail.NewClient(oc_server, oc_port)
        	if len(os_auth_url) > 0 {
                	setupAuthKeystone(client)
        	}
        	projectIObj, err := client.FindByName("project", "default-domain:" + os_tenant_name)
		if err != nil {
			fmt.Println("project err: ", err)
			os.Exit(1)
		}
		projectObj := projectIObj.(*contrailtypes.Project)
        	virtualNetworkObj := createNetwork(client, &netConf.Ipam)
        	virtualMachineObj := createVirtualMachine(client, containerName)
        	instanceIpObj := createInstanceIp(client, virtualNetworkObj)
        	ipamConfiguration := createIpamConfiguration(virtualNetworkObj, instanceIpObj)
        	virtualMachineInterfaceObj := createVirtualMachineInterface(client, virtualNetworkObj, virtualMachineObj, vethMac.String(), os_tenant_name)
        	instanceIpObj.AddVirtualMachineInterface(virtualMachineInterfaceObj)
        	client.Update(instanceIpObj)
        	client.Update(virtualMachineObj)
        	if err := netns.Do(func(_ ns.NetNS) error {
        		return ipam.ConfigureIface(vethInt, ipamConfiguration)
        	}); err != nil {
        		return err
    		}
        	contrail.VrouterAddPort(virtualMachineInterfaceObj.GetUuid(), virtualMachineObj.GetUuid(), hostVethName, vethMac.String(), virtualNetworkObj.GetName(), projectObj.GetUuid(), "NovaVMPort")
        }
        return nil
}

func createIpamConfiguration(vnObj *contrailtypes.VirtualNetwork, instIpObj *contrailtypes.InstanceIp) (
        *types.Result){
        var defaultGateway string
        var dnsServer string
        var ipPrefixLen int
        var dnsServerList []string
        ipamRefs, _ := vnObj.GetNetworkIpamRefs()
        for _, ref := range ipamRefs {
                attr := ref.Attr.(contrailtypes.VnSubnetsType)
                for _, ipamSubnet := range attr.IpamSubnets {
                        defaultGateway = ipamSubnet.DefaultGateway
                        dnsServer = ipamSubnet.DnsServerAddress
                        ipPrefixLen = ipamSubnet.Subnet.IpPrefixLen
                }
        }
        netmask := net.CIDRMask(ipPrefixLen, 32)
        ipConf := &types.IPConfig{
                IP:      net.IPNet{IP: net.ParseIP(instIpObj.GetInstanceIpAddress()), Mask: netmask},
                Gateway: net.ParseIP(defaultGateway),
        }
        dnsServerList = append(dnsServerList,dnsServer)
        dnsConf := types.DNS{
                Nameservers:    dnsServerList,
        }
        _, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
        result := &types.Result{
                IP4: ipConf,
                DNS: dnsConf,
        }
        result.IP4.Routes = append(
                result.IP4.Routes,
                types.Route{Dst: *defaultNet, GW: result.IP4.Gateway},
        )
        return result
}
      

func createVirtualMachine(client *contrail.Client, containerName string) (
        *contrailtypes.VirtualMachine){
        vm := new(contrailtypes.VirtualMachine)
        vm.SetName(containerName)
        client.Create(vm)
        vmIObj, _ := client.FindByName("virtual-machine",containerName)
        vmObj := vmIObj.(*contrailtypes.VirtualMachine)
        return vmObj

}

func createVirtualMachineInterface(client *contrail.Client, vnObj *contrailtypes.VirtualNetwork, vmObj *contrailtypes.VirtualMachine, mac string, os_tenant_name string) (
        *contrailtypes.VirtualMachineInterface){
        vmiUuidv4 := uuid.NewV4().String()
        vmiUuid := strings.Split(vmiUuidv4,"-")[0]
        vmiMac := new(contrailtypes.MacAddressesType)
        vmiMac.AddMacAddress(mac)
        vmi := new(contrailtypes.VirtualMachineInterface)
        vmi.SetFQName("project", []string{"default-domain", os_tenant_name, vmiUuid})
        vmi.SetVirtualMachineInterfaceMacAddresses(vmiMac)
        vmi.AddVirtualNetwork(vnObj)
        vmi.AddVirtualMachine(vmObj)
        client.Create(vmi)
        vmiIObj, err := client.FindByName("virtual-machine-interface","default-domain:" + os_tenant_name + ":" + vmiUuid)
        if err != nil || vmiIObj == nil{
                fmt.Fprintln(os.Stderr, err, vmiUuid)
                os.Exit(1)
        }
        vmiObj := vmiIObj.(*contrailtypes.VirtualMachineInterface)
        return vmiObj
}

func createInstanceIp(client *contrail.Client, vnObj *contrailtypes.VirtualNetwork) (
        *contrailtypes.InstanceIp){
        instanceIpUuid := uuid.NewV4().String()
        instanceIp := new(contrailtypes.InstanceIp)
        instanceIp.SetName(instanceIpUuid)
        instanceIp.AddVirtualNetwork(vnObj)
        client.Create(instanceIp)
        instanceIpIObj, err := client.FindByName("instance-ip",instanceIpUuid)
        if err != nil || instanceIpIObj == nil{
                fmt.Fprintln(os.Stderr, err)
                os.Exit(1)
        }
        instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
        instanceIpObj.ClearVirtualNetwork()
        return instanceIpObj
}

func createNetwork(client *contrail.Client, ipam *IPAMConfig)(
        *contrailtypes.VirtualNetwork) {
        var parent_id string
        var err error
        var vnUuid string
        parent_id, err = contrailconfig.GetProjectId(
                         client, os_tenant_name, "")
        if err != nil {
                fmt.Fprintln(os.Stderr, err)
                os.Exit(1)
        }
        networkList, err := client.ListByParent("virtual-network", parent_id)
        for _, n := range networkList {
                vnIObj, _ := client.FindByUuid("virtual-network", n.Uuid)
                vnObj := vnIObj.(*contrailtypes.VirtualNetwork)
                displayName := vnObj.GetDisplayName()
                if displayName == ipam.Name{
     			return vnObj
		}
        }

        fmt.Fprintln(os.Stderr, "network doesn't exist")
        subnet := net.IP(ipam.Subnet.IP).String()
        subnetSize, _ := net.IPMask(ipam.Subnet.Mask).Size()
        parent_id, err = contrailconfig.GetProjectId(
            client, os_tenant_name, "")
        fmt.Fprint(os.Stderr, parent_id)
        if err != nil {
            fmt.Fprint(os.Stderr, err)
            os.Exit(1)
        }
        vnUuid, err = contrailconfig.CreateNetworkWithSubnet(client, parent_id,
                ipam.Name, subnet + "/" + strconv.Itoa(subnetSize))
        vnIObj, err := client.FindByUuid("virtual-network", vnUuid)
        vnObj := vnIObj.(*contrailtypes.VirtualNetwork)
        if err != nil {
            fmt.Fprint(os.Stderr, err)
            os.Exit(1)
        }
        return vnObj

}

func deleteVMI(client *contrail.Client, networkName string, containerName string) {
        fqn := containerName
        vmIObj, _ := client.FindByName("virtual-machine",fqn)
	vmObj := vmIObj.(*contrailtypes.VirtualMachine)
	var vmiUuid string
        vmiRefs, _ := vmObj.GetVirtualMachineInterfaceBackRefs()
	for _, vmiRef := range vmiRefs {
        	vmiIObj, _ := client.FindByUuid("virtual-machine-interface",vmiRef.Uuid)
		vmiObj := vmiIObj.(*contrailtypes.VirtualMachineInterface)
		vmiUuid = vmiObj.GetUuid()
                virtualNetworkRefs, _ := vmiObj.GetVirtualNetworkRefs()
                for _, virtualNetworkRef := range virtualNetworkRefs{
                        vnIObj, _ := client.FindByUuid("virtual-network", virtualNetworkRef.Uuid)
                        vnObj := vnIObj.(*contrailtypes.VirtualNetwork)
                        if vnObj.GetName() == networkName {
                		instanceIpRefs, _ := vmiObj.GetInstanceIpBackRefs()
        	        	for _, instanceIpRef := range instanceIpRefs {
              	 	        	instanceIpIObj, _ := client.FindByUuid("instance-ip", instanceIpRef.Uuid)
               		        	instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
               		        	client.Delete(instanceIpObj)
                		}
                		client.Delete(vmiObj)
				contrail.VrouterDelPort(vmiUuid)
			}
		}
	}
        vmIObj, _ = client.FindByName("virtual-machine",fqn)
	vmObj = vmIObj.(*contrailtypes.VirtualMachine)
	vmiRefs, _ = vmObj.GetVirtualMachineInterfaceBackRefs()
        fmt.Print("vmiRef length: ", len(vmiRefs))
	if len(vmiRefs) == 0 {
		client.Delete(vmObj)
	}
}

func cmdDel(args *skel.CmdArgs) error {
        InitFlags()
        flag.Parse()
        containerName := args.ContainerID
        if len(containerName) > 8 {
                        var containerNameArray []string
                        var newContainerName string
                        containerNameArray = strings.SplitN(containerName,"" ,9)
                        for i := 0; i < 8; i++ {
                        newContainerName = newContainerName + containerNameArray[i]
                        }
                        fmt.Println(containerNameArray)
                        containerName = newContainerName
        }
        client := contrail.NewClient(oc_server, oc_port)
        if len(os_auth_url) > 0 {
                setupAuthKeystone(client)
        }
        netConfList, _ := loadMultiConf(args.StdinData)
        for _, netConf := range netConfList.Networks {
        	deleteVMI(client, netConf.NetworkName, containerName)
	} 
        //ipam.ExecDel(n.IPAM.Type, args.StdinData)
        return nil
}

func main() {
        skel.PluginMain(cmdAdd, cmdDel)
}
