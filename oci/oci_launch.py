"""Create subnet public (jika tiada) + lancar A1.Flex 2/12 Ubuntu 24.04 dengan retry kapasiti."""
import sys
import time
from pathlib import Path

import oci

SHAPE = "VM.Standard.A1.Flex"
OCPUS, MEM_GB = 2, 12
NAME = "secteam-a1"
SUBNET_CIDR = "10.0.0.0/24"
MAX_MINUTES = 120
INTERVAL = 60
PUBKEY = Path.home() / ".ssh" / "oci_ed25519.pub"


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


cfg = oci.config.from_file()
t = cfg["tenancy"]
idc = oci.identity.IdentityClient(cfg)
vn = oci.core.VirtualNetworkClient(cfg)
cc = oci.core.ComputeClient(cfg)

ad = idc.list_availability_domains(t).data[0].name
vcn = vn.list_vcns(t, lifecycle_state="AVAILABLE").data[0]
igw = vn.list_internet_gateways(t, vcn_id=vcn.id).data[0]
log("VCN:", vcn.display_name, "| AD:", ad)

# --- route table default -> IGW
rt = vn.get_route_table(vcn.default_route_table_id).data
if not any(r.destination == "0.0.0.0/0" for r in rt.route_rules):
    rules = list(rt.route_rules) + [oci.core.models.RouteRule(
        destination="0.0.0.0/0", destination_type="CIDR_BLOCK", network_entity_id=igw.id)]
    vn.update_route_table(rt.id, oci.core.models.UpdateRouteTableDetails(route_rules=rules))
    log("Tambah laluan 0.0.0.0/0 -> Internet Gateway pada route table default")
else:
    log("Route table default sudah ada laluan 0.0.0.0/0")

# --- security list default: pastikan SSH dibuka
sl = vn.get_security_list(vcn.default_security_list_id).data
has_ssh = any(
    r.protocol == "6" and r.tcp_options and r.tcp_options.destination_port_range
    and r.tcp_options.destination_port_range.min <= 22 <= r.tcp_options.destination_port_range.max
    for r in sl.ingress_security_rules
)
log("Security list default membenarkan SSH:", has_ssh)
if not has_ssh:
    rules = list(sl.ingress_security_rules) + [oci.core.models.IngressSecurityRule(
        protocol="6", source="0.0.0.0/0",
        tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=22, max=22)))]
    vn.update_security_list(sl.id, oci.core.models.UpdateSecurityListDetails(ingress_security_rules=rules))
    log("Tambah peraturan ingress SSH 22")

# --- subnet public
subnets = vn.list_subnets(t, vcn_id=vcn.id, lifecycle_state="AVAILABLE").data
subnet = next((s for s in subnets if not s.prohibit_public_ip_on_vnic), None)
if subnet is None:
    subnet = vn.create_subnet(oci.core.models.CreateSubnetDetails(
        compartment_id=t, vcn_id=vcn.id, cidr_block=SUBNET_CIDR, display_name="public-subnet",
        dns_label="pub", prohibit_public_ip_on_vnic=False,
        route_table_id=vcn.default_route_table_id, security_list_ids=[vcn.default_security_list_id],
    )).data
    subnet = oci.wait_until(vn, vn.get_subnet(subnet.id), "lifecycle_state", "AVAILABLE").data
    log("Subnet dicipta:", subnet.display_name, subnet.cidr_block)
else:
    log("Guna subnet sedia ada:", subnet.display_name, subnet.cidr_block)

# --- image
img = next(i for i in cc.list_images(
    t, operating_system="Canonical Ubuntu", operating_system_version="24.04", shape=SHAPE,
    sort_by="TIMECREATED", sort_order="DESC").data if "Minimal" not in i.display_name)
log("Image:", img.display_name)

# --- elak duplikat
existing = [i for i in cc.list_instances(t, display_name=NAME).data
            if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
if existing:
    log("Instance", NAME, "sudah wujud:", existing[0].lifecycle_state, existing[0].id)
    sys.exit(0)

details = oci.core.models.LaunchInstanceDetails(
    compartment_id=t, availability_domain=ad, display_name=NAME, shape=SHAPE,
    shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=OCPUS, memory_in_gbs=MEM_GB),
    source_details=oci.core.models.InstanceSourceViaImageDetails(image_id=img.id, boot_volume_size_in_gbs=50),
    create_vnic_details=oci.core.models.CreateVnicDetails(subnet_id=subnet.id, assign_public_ip=True),
    metadata={"ssh_authorized_keys": PUBKEY.read_text().strip()},
)

fds = [None, "FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]
deadline = time.time() + MAX_MINUTES * 60
attempt = 0
while True:
    attempt += 1
    details.fault_domain = fds[(attempt - 1) % len(fds)]
    try:
        inst = cc.launch_instance(details).data
        log(f"Cubaan {attempt}: BERJAYA - instance dicipta ({details.fault_domain or 'FD auto'})")
        break
    except oci.exceptions.ServiceError as e:
        msg = f"{e.status} {e.code}: {e.message}"
        if "capacity" in e.message.lower():
            log(f"Cubaan {attempt} ({details.fault_domain or 'FD auto'}): tiada kapasiti")
        elif e.status == 429:
            log(f"Cubaan {attempt}: TooManyRequests, tunggu lebih lama")
            time.sleep(INTERVAL)
        else:
            log(f"Cubaan {attempt}: RALAT TIDAK DIJANGKA - berhenti. {msg}")
            sys.exit(1)
    if time.time() > deadline:
        log(f"Tamat {MAX_MINUTES} minit tanpa kapasiti. Cuba lagi kemudian.")
        sys.exit(2)
    time.sleep(INTERVAL)

inst = oci.wait_until(cc, cc.get_instance(inst.id), "lifecycle_state", "RUNNING", max_wait_seconds=900).data
vnic_id = cc.list_vnic_attachments(t, instance_id=inst.id).data[0].vnic_id
ip = vn.get_vnic(vnic_id).data.public_ip
log("RUNNING:", inst.display_name, "| IP awam:", ip)
log(f'SSH: ssh -i "{PUBKEY.with_suffix("")}" ubuntu@{ip}')
