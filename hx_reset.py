#!/usr/bin/env python

import os
import sys
import time
import pexpect
import getpass
from threading import Thread
from ucsmsdk.ucshandle import UcsHandle
from colorama import Fore, Back, Style
from ucsmsdk.mometa.lsboot.LsbootPolicy import LsbootPolicy
from ucsmsdk.mometa.lsboot.LsbootVirtualMedia import LsbootVirtualMedia
from ucsmsdk.mometa.lsboot.LsbootEmbeddedLocalDiskImage import LsbootEmbeddedLocalDiskImage
from ucsmsdk.mometa.lsboot.LsbootUsbFlashStorageImage import LsbootUsbFlashStorageImage
from ucsmsdk.mometa.ls.LsPower import LsPower
from pyVim import connect
from pyVmomi import vim


##################
# FUNCTIONS ######
##################

def ucs_connect(ucsm_ip, ucsm_user, ucsm_pass):
    ucs_handle = UcsHandle(ucsm_ip, ucsm_user, ucsm_pass)
    ucs_handle.login()
    return ucs_handle


def org_exists(ucs_handle, org_name):
    filter_str = "(name, \""+org_name+"\")"
    object = ucs_handle.query_classid(class_id="orgOrg", filter_str=filter_str)
    if object:
        return True
    else:
        return False


def vmedia_policy_exists(ucs_handle, vmedia_policy_name):
    filter_str = "(name, \""+vmedia_policy_name+"\")"
    object = ucs_handle.query_classid(class_id="cimcvmediaMountConfigPolicy", filter_str=filter_str)
    if object:
        return True
    else:
        return False


def get_sps_in_org(ucs_handle, org_name):
    objects = ucs_handle.query_children(in_dn="org-root/org-"+org_name,class_id="lsServer",filter_str="(type,\"instance\",type=\"eq\")")
    return objects


def get_sp_template_dn(ucs_handle, sp_object):
    sp_template_dn = sp_object.oper_src_templ_name
    return sp_template_dn


def get_sp_template_boot_policy_dn(ucs_handle, sp_template_object):
    sp_template_boot_policy_object = sp_template_object.oper_boot_policy_name
    return sp_template_boot_policy_object


def get_sp_template_vmedia_policy_dn(ucs_handle, sp_template_object):
    sp_template_vmedia_policy_dn = sp_template_object.oper_vmedia_policy_name
    return sp_template_vmedia_policy_dn


def get_ucs_object_by_dn(ucs_handle, dn):
    object = ucs_handle.query_dn(dn)
    return object


def set_sp_template_vmedia_policy(ucs_handle, sp_template_object, new_vmedia_policy_dn):
    sp_template_object.vmedia_policy_name = vmedia_policy_name
    ucs_handle.set_mo(sp_template_object)
    ucs_handle.commit()
    sp_template_object = get_ucs_object_by_dn(ucs_handle, sp_template_object.dn)
    return sp_template_object


def set_vmedia_boot_policy(ucs_handle, sp_template_boot_policy_object, org_name):
    sp_template_boot_policy_name = sp_template_boot_policy_object.name
    mo = LsbootPolicy(parent_mo_or_dn="org-root/org-"+org_name, name=sp_template_boot_policy_name)
    LsbootVirtualMedia(parent_mo_or_dn=mo, access="read-only-remote-cimc", lun_id="0", order="3")
    ucs_handle.add_mo(mo, True)
    ucs_handle.commit()

    if sp_template_boot_policy_name == "HyperFlex":
        mo = LsbootUsbFlashStorageImage(parent_mo_or_dn="org-root/org-hxcluster/boot-policy-HyperFlex/storage/local-storage", order="3")
    elif sp_template_boot_policy_name == "HyperFlex-m5":
        mo = LsbootEmbeddedLocalDiskImage(parent_mo_or_dn="org-root/org-"+org_name+"/boot-policy-"+sp_template_boot_policy_name+"/storage/local-storage", order="3")
    ucs_handle.add_mo(mo, True)
    mo = LsbootVirtualMedia(parent_mo_or_dn="org-root/org-"+org_name+"/boot-policy-"+sp_template_boot_policy_name, access="read-only-remote-cimc", order="1")
    ucs_handle.add_mo(mo, True)
    mo = LsbootVirtualMedia(parent_mo_or_dn="org-root/org-"+org_name+"/boot-policy-"+sp_template_boot_policy_name, access="read-only", order="2")
    ucs_handle.add_mo(mo, True)
    ucs_handle.commit()


def sp_power_action(ucs_handle, sp_dn, action):
    mo = LsPower(parent_mo_or_dn=sp_dn, state=action)
    ucs_handle.add_mo(mo, True)
    ucs_handle.commit()


def get_sp_kvm_ips(ucs_handle, sp_objects):
    sp_kvm_ips = {}
    for sp_object in sp_objects:
        kvm_ip = ucs_handle.query_children(in_dn=sp_object.dn,class_id="vnicIpV4PooledAddr")[0].addr
        sp_kvm_ips.update( {sp_object.name:kvm_ip} )
    return sp_kvm_ips


def monitor_esxi_prompt(sp_name, sp_kvm_ip):
    ssh_newkey = "Are you sure you want to continue connecting"
    cmd = "ssh -l %s %s -oKexAlgorithms=diffie-hellman-group1-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" % (ucsm_user, sp_kvm_ip)
    kvm_session = pexpect.spawn(cmd, timeout=60)
    kvm_session.timeout=600
    i = kvm_session.expect([ssh_newkey, '[Pp]assword:'])
    if i == 0:
        kvm_session.sendline("yes")
        kvm_session.expect("[Pp]assword:")
    time.sleep(5)
    kvm_session.sendline(ucsm_pass)
    kvm_session.expect("Connection to Exit|Exit the session")
    kvm_session.sendcontrol('d')
    time.sleep(2)
    kvm_session.expect("login:")
    kvm_session.sendline("root")
    kvm_session.expect("[Pp]assword:")
    kvm_session.sendline("Cisco123")
    kvm_session.expect(":~]")
    print ("   <> Successfully connected to ESXi CLI prompt on service profile: "+sp_name)


def get_phys_server_dns(ucs_handle, sp_objects):
    phy_server_dns = []
    for object in sp_objects:
        phy_server_dns.append(object.pn_dn)
    return phy_server_dns


def monitor_phy_server_assoc(ucs_handle, phy_server_dn):
    timeout = 1800
    timepassed = 0
    while True:
        object = get_ucs_object_by_dn(ucs_handle, phy_server_dn)
        association = object.association
        availability = object.availability
        if association == "none" and availability == "available":
            print ("   <> Physical server: "+phy_server_dn+" successfully dissassociated.")
            return
        else:
            time.sleep(60)
            timepassed += 60
            if timepassed >= timeout:
                print ("timed out waiting for dissassociation of physical server: "+phy_server_dn)
                sys.exit()


def delete_org(ucs_handle, org_name):
    filter_str = "(name, \""+org_name+"\")"
    org_object = ucs_handle.query_classid(class_id="orgOrg", filter_str=filter_str)[0]
    ucs_handle.remove_mo(org_object)
    ucs_handle.commit()


def ucs_disconnect(ucs_handle):
    ucs_handle.logout()


def vcenter_connect(vcenter_ip, vcenter_user, vcenter_pass):
    vcenter_handle = connect.SmartConnectNoSSL(host=vcenter_ip, user=vcenter_user, pwd=vcenter_pass)
    return vcenter_handle


def get_cluster(vcenter_handle, vcenter_dc, vcenter_cluster):
    clusters = vcenter_handle.content.viewManager.CreateContainerView(vcenter_handle.content.rootFolder, [vim.ClusterComputeResource], True)
    for cluster_object in clusters.view:
        if cluster_object.name == vcenter_cluster and cluster_object.parent.parent.name == vcenter_dc:
            return cluster_object

def dc_exists(vcenter_handle, vcenter_dc):
    datacenters = vcenter_handle.content.viewManager.CreateContainerView(vcenter_handle.content.rootFolder, [vim.Datacenter], True)
    for dc in datacenters.view:
        if dc.name == vcenter_dc:
            return True
    return False


def cluster_exists(vcenter_handle, vcenter_dc, vcenter_cluster):
    clusters = vcenter_handle.content.viewManager.CreateContainerView(vcenter_handle.content.rootFolder, [vim.ClusterComputeResource], True)
    for cluster in clusters.view:
        if cluster.name == vcenter_cluster and cluster.parent.parent.name == vcenter_dc:
            return True
    return False


def delete_vcenter_cluster(vcenter_handle, cluster_object):
    cluster_object.Destroy()


def delete_vcenter_extension(vcenter_handle, ext_name):
    extensions = vcenter_handle.content.extensionManager.extensionList
    for ext in extensions:
        if ext_name in ext.key:
            vcenter_handle.content.extensionManager.UnregisterExtension(ext_name)


def get_hx_extensions(vcenter_handle):
    extensions = vcenter_handle.content.extensionManager.extensionList
    hx_extensions = []
    for ext in extensions:
        if "springpath" in ext.key:
            hx_extensions.append(ext.key)
    return hx_extensions


def vcenter_disconnect(vcenter_handle):
    connect.Disconnect(vcenter_handle)



##################
# MAIN ###########
##################

print ("\n")
print (Style.BRIGHT+"WARNING!!!"+Style.RESET_ALL)
print ("The following script will completely erase a HyperFlex configuration including the data, which will not be recoverable afterwards.")
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 1: Get Environment Details"+Style.RESET_ALL)
print ("\n")


while True:

    print (Style.BRIGHT+Fore.WHITE+"Choose the number that best describes your HyperFlex cluster:"+Style.RESET_ALL)
    print ("\n")

    print ("     1. Standard HyperFlex with Fabric Interconnects")
    print ("     2. HyperFlex Edge with Intersight")
    print ("     3. HyperFlex Edge without Intersight")

    cluster_type = raw_input(Style.BRIGHT+Fore.WHITE+"Selection: "+Style.RESET_ALL)
    if cluster_type is in ("1","2","3"):
        break
    else:
        print ("   <> Not a valid entry, please retry...")


print (Style.BRIGHT+Fore.WHITE+"Gathering UCS Details..."+Style.RESET_ALL)
print ("\n")

while True:
    ucsm_ip = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Manager IP address: "+Style.RESET_ALL)
    ucsm_user = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Manager username: "+Style.RESET_ALL)
    ucsm_pass = getpass.getpass(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Manager password: "+Style.RESET_ALL)
    try:
        ucs_handle = ucs_connect(ucsm_ip, ucsm_user, ucsm_pass)
        if ucs_handle:
            print ("   <> Successfully connected to UCS Manager.")
            break
    except:
        print ("   <> Unable to connect to UCS Mananger with the provided details, please retry...")

while True:
    org_name = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Org associated with the HyperFlex cluster: "+Style.RESET_ALL)
    if org_exists(ucs_handle, org_name):
        print ("   <> Successfully found UCS Org.")
        break
    else:
        print ("   <> Provided UCS Org does not exist, please retry...")

while True:
    vmedia_policy_name = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS vMedia policy name to be used for re-imaging the HyperFlex nodes: "+Style.RESET_ALL)
    if vmedia_policy_exists(ucs_handle, vmedia_policy_name):
        print ("   <> Successfully found vMedia policy.")
        break
    else:
        print ("   <> Provided UCS vMedia policy does not exist, please retry...")

ucs_disconnect(ucs_handle)
print ("\n")


print (Style.BRIGHT+Fore.WHITE+"Gathering vCenter Details..."+Style.RESET_ALL)
print ("\n")

while True:
    vcenter_ip = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the vCenter IP address: "+Style.RESET_ALL)
    vcenter_user = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the vCenter username: "+Style.RESET_ALL)
    vcenter_pass = getpass.getpass(Style.BRIGHT+Fore.WHITE+"Please enter the vCenter password: "+Style.RESET_ALL)
    try:
        vcenter_handle = vcenter_connect(vcenter_ip, vcenter_user, vcenter_pass)
        if vcenter_handle:
            print ("   <> Successfully connected to vCenter.")
            break
    except:
        print ("   <> Unable to connect to vCenter with the provided details, please retry...")

while True:
    vcenter_dc = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the VMware Datacenter name containing the HyperFlex cluster: "+Style.RESET_ALL)
    if dc_exists(vcenter_handle, vcenter_dc):
        print ("   <> Successfully found VMware Datacenter.")
        break
    else:
        print ("   <> Provided VMware Datacenter does not exist, please retry...")

while True:
    vcenter_cluster = raw_input(Style.BRIGHT+Fore.WHITE+"Please enter the VMware Cluster name associated with the HyperFlex cluster: "+Style.RESET_ALL)
    if cluster_exists(vcenter_handle, vcenter_dc, vcenter_cluster):
        print ("   <> Successfully found VMware Cluster.")
        break
    else:
        print ("   <> Provided VMware Cluster does not exist, please retry...")

vcenter_disconnect(vcenter_handle)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 1 COMPLETED: Get Environment Details"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 2: Re-image HyperFlex Nodes"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to UCS Manager..."+Style.RESET_ALL)
ucs_handle = ucs_connect(ucsm_ip, ucsm_user, ucsm_pass)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching service profiles in the provided ucs org..."+Style.RESET_ALL)
sp_objects = get_sps_in_org(ucs_handle, org_name)
for sp_object in sp_objects:
    print ("   <> Item: Service Profile, Name: "+sp_object.name+", DN: "+sp_object.dn)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching related service profile template..."+Style.RESET_ALL)
sp_template_dn = get_sp_template_dn(ucs_handle, sp_objects[0])
sp_template_object = get_ucs_object_by_dn(ucs_handle, sp_template_dn)
print ("   <> Item: Service Profile Template, Name: "+sp_template_object.name+", DN: "+sp_template_object.dn)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching related service profile template boot policy information..."+Style.RESET_ALL)
sp_template_boot_policy_dn = get_sp_template_boot_policy_dn(ucs_handle, sp_template_object)
sp_template_boot_policy_object = get_ucs_object_by_dn(ucs_handle, sp_template_boot_policy_dn)
print ("   <> Item: Service Profile Template Boot Policy, Name: "+sp_template_boot_policy_object.name+", DN: "+sp_template_boot_policy_object.dn)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching current service profile template vmedia policy information..."+Style.RESET_ALL)
sp_template_vmedia_policy_dn = get_sp_template_vmedia_policy_dn(ucs_handle, sp_template_object)
if not sp_template_vmedia_policy_dn:
    print ("   <> Item: Service Profile Template vMedia Policy, Name: <None>, DN: <None>")
else:
    sp_template_vmedia_policy_object = get_ucs_object_by_dn(ucs_handle, sp_template_vmedia_policy_dn)
    print ("   <> Item: Current Service Profile Template vMedia Policy, Name: "+sp_template_vmedia_policy_object.name+", DN: "+sp_template_vmedia_policy_object.dn)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Setting new service profile template vmedia policy..."+Style.RESET_ALL)
sp_template_object = set_sp_template_vmedia_policy(ucs_handle, sp_template_object, vmedia_policy_name)
sp_template_vmedia_policy_dn = get_sp_template_vmedia_policy_dn(ucs_handle, sp_template_object)
sp_template_vmedia_policy_object = get_ucs_object_by_dn(ucs_handle, sp_template_vmedia_policy_dn)
print ("   <> Item: New Service Profile Template vMedia Policy, Name: "+sp_template_vmedia_policy_object.name+", DN: "+sp_template_vmedia_policy_object.dn)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Setting vmedia policy as first boot item in service profile template boot policy..."+Style.RESET_ALL)
set_vmedia_boot_policy(ucs_handle, sp_template_boot_policy_object, org_name)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Rebooting service profiles in provided ucs org..."+Style.RESET_ALL)
for sp_object in sp_objects:
    sp_power_action(ucs_handle, sp_object.dn, "hard-reset-immediate")
    print ("   <> Rebooting service profile: "+sp_object.name)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Disconnecting from UCS Manager..."+Style.RESET_ALL)
ucs_disconnect(ucs_handle)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Going to sleep while hyperflex nodes are re-imaged, this can take ~25-30 minutes due to multiple required reboots during install..."+Style.RESET_ALL)
for i in xrange(500,0,-1):
    sys.stdout.write(str('.'))
    sys.stdout.flush()
    time.sleep(3)
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waking up..."+Style.RESET_ALL)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to UCS Manager..."+Style.RESET_ALL)
ucs_handle = ucs_connect(ucsm_ip, ucsm_user, ucsm_pass)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Getting service profile kvm ip addresses..."+Style.RESET_ALL)
sp_objects = get_sps_in_org(ucs_handle, org_name)
sp_kvm_ips = get_sp_kvm_ips(ucs_handle, sp_objects)
for key, value in sp_kvm_ips.iteritems():
    print ("   <> Item: Service Profile, Name: "+key+", KVM IP: "+value)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waiting for access to ESXi CLI prompt for service profiles, this can take another couple of minutes..."+Style.RESET_ALL)
threads = []
for key, value in sp_kvm_ips.iteritems():
    print ("   <> Waiting to connect to ESXi CLI prompt on service profile: "+key)
    thread = Thread(target=monitor_esxi_prompt, args=(key, value,))
    threads.append(thread)
    thread.start()
for thread in threads:
    thread.join()
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Gracefully powering-off service profiles..."+Style.RESET_ALL)
for sp_object in sp_objects:
    sp_power_action(ucs_handle, sp_object.dn, "soft-shut-down-only")
    print ("   <> Powering-off service profile: "+sp_object.name)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 2 COMPLETED: Re-image HyperFlex Nodes"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 3: Clean-up HyperFlex Config in UCS Manager"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Getting list of physical rack servers supporting HyperFlex service profiles..."+Style.RESET_ALL)
phy_server_dns = get_phys_server_dns(ucs_handle, sp_objects)
for phy_server in phy_server_dns:
    print ("   <> Item: Physical Server, DN: "+phy_server)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting org \""+org_name+"\" in UCS Manager..."+Style.RESET_ALL)
delete_org(ucs_handle, org_name)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waiting for complete dissassociation of physical servers..."+Style.RESET_ALL)
threads = []
for phy_server in phy_server_dns:
    thread = Thread(target=monitor_phy_server_assoc, args=(ucs_handle, phy_server,))
    threads.append(thread)
    thread.start()
for thread in threads:
    thread.join()



print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Disconnecting from UCS Manager..."+Style.RESET_ALL)
ucs_disconnect(ucs_handle)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 3 COMPLETED: Clean-up HyperFlex Config in UCS Manager"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 4: Clean-up HyperFlex Config in vCenter"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to vCenter..."+Style.RESET_ALL)
vcenter_handle = vcenter_connect(vcenter_ip, vcenter_user, vcenter_pass)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting HyperFlex vCenter extensions..."+Style.RESET_ALL)
cluster_object = get_cluster(vcenter_handle, vcenter_dc, vcenter_cluster)
cluster_ext_name = "com.springpath.sysmgmt."+cluster_object._moId
delete_vcenter_extension(vcenter_handle, cluster_ext_name)
hx_extensions = get_hx_extensions(vcenter_handle)
if len(hx_extensions) == 1 and hx_extensions[0] == "com.springpath.sysmgmt":
    print ("   <> Only one HyperFlex cluster found, also deleting \"com.springpath.sysmgmt\" extension.")
    delete_vcenter_extension(vcenter_handle, "com.springpath.sysmgmt")
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting HyperFlex ESXi cluster in vCenter..."+Style.RESET_ALL)
cluster_object.Destroy()
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 4 COMPLETED: Clean-up HyperFlex Config in vCenter"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"HyperFlex Reset Completed!!!"+Style.RESET_ALL)
print ("\n")
