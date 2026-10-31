import ssl
from pyVim.connect import SmartConnect
from pyVmomi import vim

si = SmartConnect(host="10.19.170.146", user="inventory@vsphere.local",
                  pwd="Happy@year@123", sslContext=ssl._create_unverified_context())
content = si.RetrieveContent()

for kind, name in [(vim.Datacenter, "Datacenter"),
                   (vim.ClusterComputeResource, "Cluster"),
                   (vim.HostSystem, "Host"),
                   (vim.Datastore, "Datastore"),
                   (vim.VirtualMachine, "VM")]:
    view = content.viewManager.CreateContainerView(content.rootFolder, [kind], True)
    print(f"{name}: {len(view.view)}")
    view.Destroy()
