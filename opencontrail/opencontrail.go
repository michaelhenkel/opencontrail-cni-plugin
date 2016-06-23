//
// Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
//

package main

import (
	"github.com/michaelhenkel/contrail-go-api"
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
        n, err := loadNetConf(args.StdinData)
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
        vethMac, hostVethName, err := setupVeth(netns, args.IfName, n.MTU)
        var instanceIpName string
        var vnUuid string
        InitFlags(n)
        flag.Parse()
        if err != nil {
                return err
        }
        result, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
        if err != nil {
                return err
        }
        for _, customAttribute := range result.CUSTOMATTR.CustomAttributes {
                if customAttribute.Name == "instanceIpName" {
			instanceIpName = customAttribute.Value
		}
                if customAttribute.Name == "vnUuid" {
			vnUuid = customAttribute.Value
		}

        }
		
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
        vm := new(contrailtypes.VirtualMachine)
	vm.SetName(containerName)
        client.Create(vm)
        instanceIpIObj, err := client.FindByName("instance-ip",instanceIpName)
        instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
        vnIObj, err := client.FindByUuid("virtual-network", vnUuid)
        vnObj := vnIObj.(*contrailtypes.VirtualNetwork)
	vmiUuidv4 := uuid.NewV4().String()
        vmiUuid := strings.Split(vmiUuidv4,"-")[0]
        vmiMac := new(contrailtypes.MacAddressesType)
        vmiMac.AddMacAddress(vethMac.String())
        vmi := new(contrailtypes.VirtualMachineInterface) 
        vmi.SetFQName("project", []string{"default-domain", os_tenant_name, vmiUuid})
        vmi.SetVirtualMachineInterfaceMacAddresses(vmiMac)
        vmi.AddVirtualNetwork(vnObj)
        vmi.AddVirtualMachine(vm)
        client.Create(vmi)
        instanceIpObj.AddVirtualMachineInterface(vmi)
        client.Update(instanceIpObj)
        client.Update(vm)
	_, defaultNet, err := net.ParseCIDR("0.0.0.0/0")
	result.IP4.Routes = append(
                result.IP4.Routes,
                types.Route{Dst: *defaultNet, GW: result.IP4.Gateway},
        )
        if err := netns.Do(func(_ ns.NetNS) error {
        	return ipam.ConfigureIface(args.IfName, result)
        }); err != nil {
        	return err
    	}
        
        vrouterAddPort(vmi.GetUuid(), vm.GetUuid(), hostVethName, vethMac.String(), vnObj.GetName(), projectObj.GetUuid(), "NovaVMPort")
        return nil
}

func deleteVMI(client *contrail.Client, networkName string, containerName string) {
        //fqn := "default-domain:" + os_tenant_name + ":" + containerName
        fqn := containerName
        vmIObj, _ := client.FindByName("virtual-machine",fqn)
	vmObj := vmIObj.(*contrailtypes.VirtualMachine)
	var vmiUuid string
        vmiRefs, _ := vmObj.GetVirtualMachineInterfaceBackRefs()
	for _, vmiRef := range vmiRefs {
        	vmiIObj, _ := client.FindByUuid("virtual-machine-interface",vmiRef.Uuid)
		vmiObj := vmiIObj.(*contrailtypes.VirtualMachineInterface)
		vmiUuid = vmiObj.GetUuid()
		instanceIpRefs, _ := vmiObj.GetInstanceIpBackRefs()
		for _, instanceIpRef := range instanceIpRefs {
                	instanceIpIObj, _ := client.FindByUuid("instance-ip", instanceIpRef.Uuid)
                	instanceIpObj := instanceIpIObj.(*contrailtypes.InstanceIp)
                	client.Delete(instanceIpObj)
        	}
        	client.Delete(vmiObj)
	}
	vrouterDelPort(vmiUuid)
	client.Delete(vmObj)
}

func cmdDel(args *skel.CmdArgs) error {
        n, err := loadNetConf(args.StdinData)
        if err != nil {
                return err
        }
        InitFlags(n)
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
        deleteVMI(client, n.NetworkName, containerName)
        //ipam.ExecDel(n.IPAM.Type, args.StdinData)
        return nil
}

func main() {
        skel.PluginMain(cmdAdd, cmdDel)
}
