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
	"github.com/alexcesaro/log"
        "github.com/alexcesaro/log/golog"
	"bytes"
        "encoding/json"
	"io/ioutil"
	"time"
        "runtime"
	"flag"
	"fmt"
	"os"
        "io"
        "net"
        "strings"
        "strconv"
	"bufio"
	"net/http"
	//"reflect"
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
        logger log.Logger
        debug string
	logToStderr        *bool
	commandMap map[string]CliCommand = make(map[string]CliCommand, 0)
	//portMap map[string]PortStruct = make(map[string]PortStruct)
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
	Networks      []NetConf `json:"networks"`
        ApiServer     string `json:"api_server"`
        ApiPort       int `json:"api_port"`
        AuthUrl       string `json:"auth_url"`
        TenantName    string `json:"tenant_name"`
        AdminUser     string `json:"admin_user"`
        AdminPassword string `json:"admin_password"`
        AdminToken    string `json:"admin_token"`
}

type Result struct {
    Ipv4    *IP    `json:"ipv4"`
    Dns    *DNS    `json:"dns"`
}

type IP struct {
        Ip    string    `json:"ip"`
    	Gateway    string    `json:"gateway"`    
}

type DNS struct {
    Nameservers    []string `json:"nameservers"`
}

func loadMultiConf(bytes []byte) (*MultiConf, error) {
	netConfList := &MultiConf{}
        json.Unmarshal(bytes, netConfList)
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
    InitFlags()
    flag.Parse()
    out := getStream(true)
    logLevel := getLevelFromName(debug)
    logger = golog.New(out, logLevel)
}

func getLevelFromName(levelName string) (level log.Level) {
    switch levelName {
    case "debug":
        level = log.Debug
    case "info":
        level = log.Info
    case "notice":
        level = log.Notice
    case "warning":
        level = log.Warning
    case "error":
        level = log.Error
    case "critical":
        level = log.Critical
    case "alert":
        level = log.Alert
    case "emergency":
        level = log.Emergency
    case "none":
        level = log.None
    default:
        level = log.None
    }

    return
}

var getStream = func(logToStderr bool) io.Writer {
    if logToStderr {
        return os.Stderr
    }

    return os.Stdout
}

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
        flag.StringVar(&debug, "debug", os.Getenv("LOG_LEVEL"), "Log Level (Env: LOG_LEVEL)")
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

type Port struct {
    Id         	string        `json:"id"`
    InstanceId  string        `json:"instance-id"`
    Ipv4Address	string        `json:"ip-address"`
    Ipv6Address	string        `json:"ip6-address"`
    VnId        string        `json:"vn-id"`
    DisplayName string        `json:"display-name"`
    ProjectId   string        `json:"vm-project-id"`
    MacAddress  string        `json:"mac-address"`
    SystemName  string        `json:"system-name"`
    Type        int	      `json:"type"`
    RxVlanId    int           `json:"rx-vlan-id"`
    TxVlanId    int           `json:"tx-vlan-id"`
    Author      string        `json:"author"`
    Time        string        `json:"time"`
}

func cmdAdd(args *skel.CmdArgs) error {
	var vethInt string
	var hostVethName string
        var err error
        var vethMac net.HardwareAddr
	var virtualNetworkObj *contrailtypes.VirtualNetwork
	var virtualMachineObj *contrailtypes.VirtualMachine
	var instanceIpObj *contrailtypes.InstanceIp
	var virtualMachineInterfaceObj *contrailtypes.VirtualMachineInterface
	var ipamConfiguration *types.Result
	url := "http://localhost:9091/port"
        vethIntNumber := 0
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
        netConf, _ := loadNetConf(args.StdinData)
        if netConf.ApiServer != "" {
            oc_server = netConf.ApiServer
        }
        if netConf.ApiPort != 0 {
            oc_port = netConf.ApiPort
        }
        if netConf.TenantName != "" {
            os_tenant_name = netConf.TenantName
        }
        if netConf.AuthUrl != "" {
            os_auth_url = netConf.AuthUrl
        }
        if netConf.AdminUser != "" {
            os_username = netConf.AdminUser
        }
        if netConf.AdminPassword != "" {
            os_password = netConf.AdminPassword
        }
        client := contrail.NewClient(oc_server, oc_port)
        if len(os_auth_url) > 0 {
                setupAuthKeystone(client)
        }
        projectIObj, _ := client.FindByName("project", "default-domain:" + os_tenant_name)
        projectObj := projectIObj.(*contrailtypes.Project)
                vethInt = "eth" + strconv.Itoa(vethIntNumber)
                vethIntNumber = vethIntNumber + 1
                netConf.Ipam.Name = netConf.NetworkName
		vethMac, hostVethName, err = setupVeth(netns, vethInt, netConf.MTU)
        	virtualNetworkObj = createNetwork(client, &netConf.Ipam)
        	virtualMachineObj = createVirtualMachine(client, containerName)
        	instanceIpObj = createInstanceIp(client, virtualNetworkObj)
        	ipamConfiguration = createIpamConfiguration(virtualNetworkObj, instanceIpObj)
        	virtualMachineInterfaceObj = createVirtualMachineInterface(client, virtualNetworkObj, virtualMachineObj, vethMac.String(), os_tenant_name, hostVethName)
        	instanceIpObj.AddVirtualMachineInterface(virtualMachineInterfaceObj)
        	client.Update(instanceIpObj)
        	client.Update(virtualMachineObj)
        	if err := netns.Do(func(_ ns.NetNS) error {
        		return ipam.ConfigureIface(vethInt, ipamConfiguration)
        	}); err != nil {
        		return err
    		}
		portJson := Port{
        		Id: 		virtualMachineInterfaceObj.GetUuid(),
			InstanceId: 	virtualMachineObj.GetUuid(),
			Ipv4Address:	instanceIpObj.GetInstanceIpAddress(),
			VnId:		virtualNetworkObj.GetUuid(),
			DisplayName:	virtualMachineObj.GetName(),
			ProjectId:	projectObj.GetUuid(),
			MacAddress:	vethMac.String(),
			SystemName:	hostVethName,
			Type:		0,
			Time:		time.Now().String(),
    		}
		j, err := json.Marshal(portJson)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(j))
		req.Header.Set("Content-Type", "application/json")
		http_client := &http.Client{}
		resp, err := http_client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		ioutil.ReadAll(resp.Body)
		writeToFile(virtualMachineInterfaceObj.GetUuid(), portJson)
/*
                fmt.Print("ipam conf: ", ipamConfiguration, "\n")
                fmt.Print("ip conf: ", ipamConfiguration.IP4, "\n")
                fmt.Print("gw conf: ", ipamConfiguration.IP4.Gateway, "\n")
                fmt.Print("dns conf: ", ipamConfiguration.DNS.Nameservers, "\n")
*/
                ip := &IP{
                    Ip: instanceIpObj.GetInstanceIpAddress(),
                    Gateway: ipamConfiguration.IP4.Gateway.String(),
                }
                dns := &DNS{
                    Nameservers: ipamConfiguration.DNS.Nameservers,
                }
                result := &Result{
                    Ipv4: ip,
                    Dns: dns,
                }
                b, _ := json.Marshal(result)
                fmt.Println(string(b))
        return nil
}

func writeToFile(uuid string, portJson Port){
	portFilePath := "/var/lib/contrail/ports/" + uuid
	j, _ := json.Marshal(portJson)
	f, _ := os.Create(portFilePath)
	w := bufio.NewWriter(f)
	_, _ = w.WriteString(string(j))
	w.Flush()
	defer f.Close()
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
        vmIObj, _ := client.FindByName("virtual-machine",containerName)
        if vmIObj == nil{
        	vm := new(contrailtypes.VirtualMachine)
        	vm.SetName(containerName)
        	client.Create(vm)
        	vmIObj, _ := client.FindByName("virtual-machine",containerName)
        	vmObj := vmIObj.(*contrailtypes.VirtualMachine)
        	return vmObj
	}else{
        	vmObj := vmIObj.(*contrailtypes.VirtualMachine)
        	return vmObj
	}

}

func createVirtualMachineInterface(client *contrail.Client, vnObj *contrailtypes.VirtualNetwork, vmObj *contrailtypes.VirtualMachine, mac string, os_tenant_name string, hostVethName string) (
        *contrailtypes.VirtualMachineInterface){
        vmiMac := new(contrailtypes.MacAddressesType)
        vmiMac.AddMacAddress(mac)
        vmi := new(contrailtypes.VirtualMachineInterface)
        vmi.SetFQName("project", []string{"default-domain", os_tenant_name, hostVethName})
        vmi.SetVirtualMachineInterfaceMacAddresses(vmiMac)
        vmi.AddVirtualNetwork(vnObj)
        vmi.AddVirtualMachine(vmObj)
        client.Create(vmi)
        vmiIObj, err := client.FindByName("virtual-machine-interface","default-domain:" + os_tenant_name + ":" + hostVethName)
        if err != nil || vmiIObj == nil{
                fmt.Fprintln(os.Stderr, err, hostVethName)
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

        subnet := net.IP(ipam.Subnet.IP).String()
        subnetSize, _ := net.IPMask(ipam.Subnet.Mask).Size()
        parent_id, err = contrailconfig.GetProjectId(
            client, os_tenant_name, "")
        if err != nil {
            os.Exit(1)
        }
        vnUuid, err = contrailconfig.CreateNetworkWithSubnet(client, parent_id,
                ipam.Name, subnet + "/" + strconv.Itoa(subnetSize))
        vnIObj, err := client.FindByUuid("virtual-network", vnUuid)
        vnObj := vnIObj.(*contrailtypes.VirtualNetwork)
        if err != nil {
            os.Exit(1)
        }
        return vnObj

}


func deleteVirtualMachineInterface(client *contrail.Client, networkName string, containerName string) {
        fqn := containerName
        vmIObj, _ := client.FindByName("virtual-machine",fqn)
        if vmIObj != nil{
		vmObj := vmIObj.(*contrailtypes.VirtualMachine)
        	vmiRefs, _ := vmObj.GetVirtualMachineInterfaceBackRefs()
        	if len(vmiRefs) > 0 {
			for _, vmiRef := range vmiRefs {
      	 		 	vmiIObj, _ := client.FindByUuid("virtual-machine-interface",vmiRef.Uuid)
				vmiObj := vmiIObj.(*contrailtypes.VirtualMachineInterface)
				virtualNetworkRefs, _ := vmiObj.GetVirtualNetworkRefs()
				for _, virtualNetworkRef := range virtualNetworkRefs{
					vnIObj, _ := client.FindByUuid("virtual-network", virtualNetworkRef.Uuid)
      	 		                vnObj := vnIObj.(*contrailtypes.VirtualNetwork)
      	 		                if vnObj.GetDisplayName() == networkName {
      	 		         		instanceIpRefs, _ := vmiObj.GetInstanceIpBackRefs()
      	 		 	        	for _, instanceIpRef := range instanceIpRefs {
      	 		       	 	        	instanceIpIObj, _ := client.FindByUuid("instance-ip", instanceIpRef.Uuid)
      	 	        		        	instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
      	 	        		        	client.Delete(instanceIpObj)
      	 		         		}
       			         		client.Delete(vmiObj)
                       				url := "http://localhost:9091/port/" + vmiObj.GetUuid()
                        			req, err := http.NewRequest("DELETE", url, nil)
                        			req.Header.Set("Content-Type", "application/json")
                        			client := &http.Client{}
                        			resp, err := client.Do(req)
                        			if err != nil {
                                			panic(err)
                        			}
                        			defer resp.Body.Close()
					}
				}
			}
		}
        	vmIObj, _ = client.FindByName("virtual-machine",fqn)
		vmObj = vmIObj.(*contrailtypes.VirtualMachine)
		vmiRefs, _ = vmObj.GetVirtualMachineInterfaceBackRefs()
		if len(vmiRefs) == 0 {
			client.Delete(vmObj)
		}
	}
}
func deleteVirtualNetwork(client *contrail.Client, networkName string) {
	parent_id, err := contrailconfig.GetProjectId(
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
                if displayName == networkName {
			virtualMachineInterfaceRefs, _ := vnObj.GetVirtualMachineInterfaceBackRefs()
			if len(virtualMachineInterfaceRefs) == 0{
				client.Delete(vnObj)
			}
                }
        }
}

func cmdDel(args *skel.CmdArgs) error {
	var ipn *net.IPNet
        var err error
        containerName := args.ContainerID
	//portMap := make(map[string]PortStruct)
        if len(containerName) > 8 {
                        var containerNameArray []string
                        var newContainerName string
                        containerNameArray = strings.SplitN(containerName,"" ,9)
                        for i := 0; i < 8; i++ {
                        newContainerName = newContainerName + containerNameArray[i]
                        }
                        containerName = newContainerName
        }
        client := contrail.NewClient(oc_server, oc_port)
        if len(os_auth_url) > 0 {
                setupAuthKeystone(client)
        }
        vethIntNumber := 0
        netConf, _ := loadNetConf(args.StdinData)
        	deleteVirtualMachineInterface(client, netConf.NetworkName, containerName)
		vethInt := "eth" + strconv.Itoa(vethIntNumber)
                vethIntNumber = vethIntNumber + 1
    		err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
        		ipn, err = ip.DelLinkByNameAddr(vethInt, netlink.FAMILY_V4)
        		return err
    		})
    		if err != nil {
        		return err
    		}
        	//deleteVirtualNetwork(client, netConf.NetworkName)
        return nil
}

func main() {
        skel.PluginMain(cmdAdd, cmdDel)
}
