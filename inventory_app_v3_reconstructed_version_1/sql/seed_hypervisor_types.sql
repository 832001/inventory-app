UPDATE hypervisor_types
   SET adapter_module='adapters.vmware.adapter',
       adapter_class='VMwareAdapter',
       capabilities='{"clusters":true,"hosts":true,"datastores":true,"vms":true,"datacenters":true,"vm_disks":true,"vm_nics":true,"vm_disk_usage":true}'
 WHERE type_key='vmware';

UPDATE hypervisor_types
   SET adapter_module='adapters.hyperv.adapter',
       adapter_class='HypervAdapter',
       capabilities='{"clusters":true,"hosts":true,"datastores":true,"vms":true,"datacenters":false,"vm_disks":true,"vm_nics":false,"vm_disk_usage":false}'
 WHERE type_key='hyperv';

-- Optional scaffolds for later
INSERT IGNORE INTO hypervisor_types
   (type_key, display_name, adapter_module, adapter_class, adapter_version, icon, enabled, capabilities)
VALUES
   ('proxmox','Proxmox VE','adapters.proxmox.adapter','ProxmoxAdapter','0.0.1','bi-box',0,
    '{"clusters":true,"hosts":true,"datastores":true,"vms":true,"datacenters":false,"vm_disks":false,"vm_nics":false,"vm_disk_usage":false}'),
   ('nutanix','Nutanix Prism','adapters.nutanix.adapter','NutanixAdapter','0.0.1','bi-hdd-stack',0,
    '{"clusters":true,"hosts":true,"datastores":true,"vms":true,"datacenters":false,"vm_disks":false,"vm_nics":false,"vm_disk_usage":false}');
