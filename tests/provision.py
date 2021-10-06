#!/usr/bin/env python3
import os
from datetime import date, datetime, time
from time import sleep

from tests import run, rapido_dir

hostnames_to_create = {'tcpls-client', 'tcpls-server'}
devices = run('metal devices list -o json') or []

for d in devices:
    if d['hostname'] in hostnames_to_create:
        print("Found", d['hostname'])
        hostnames_to_create.remove(d['hostname'])

tonight = datetime.combine(date.today(), time(23, 00))

for h in hostnames_to_create:
    print("Creating", h)
    run(f'metal devices create -H {h} -P c3.small.x86 -m AM -O centos_8 -T {tonight.isoformat()}Z -o json')

devices = run('metal devices list -o json')
print("Waiting for machines to boot")
while any([d['state'] != 'active' for d in devices]):
    print('.', end='')
    devices = run('metal devices list -o json')
    sleep(1)

print("All machines active")

nodes = {}
for d in devices:
    nodes[d['hostname']] = f"root@{d['ip_addresses'][0]['address']}"
    run(f"ssh-keygen -R {d['ip_addresses'][0]['address']}")
    assert run(f"ssh -oStrictHostKeyChecking=accept-new {nodes[d['hostname']]} echo Hello") == 0


def provision(node):
    print("Provisioning", node)
    if run(f"ssh {node} cat .provisioned", stderr=False) != 0:
        run(f'ssh {node} dnf install -y epel-release', stdout=None)
        run(f'ssh {node} dnf install -y cmake openssl openssl-devel libarchive gcc gcc-c++ gdb strace valgrind', stdout=None)
        run(f"ssh {node} touch .provisioned")

    run(f'rsync -r --exclude .git --exclude "cmake-*" --exclude "CMakeFiles" --exclude CMakeCache.txt {rapido_dir} {node}:', stdout=None)
    run(f'ssh {node} rm -rf rapido/CMakeFiles rapido/CMakeCache.txt', stdout=None)
    run(f"ssh {node} 'cd rapido && cmake .'", stdout=None)
    run(f"ssh {node} 'cd rapido && make rapido'", stdout=None)



provision(nodes['tcpls-client'])
provision(nodes['tcpls-server'])

print("All machines provisioned")
print(nodes)

for n, a in nodes.items():
    cluster_dir = os.path.join(rapido_dir, 'tests', 'npf_tests', 'cluster')
    os.makedirs(cluster_dir, exist_ok=True)
    with open(os.path.join(cluster_dir, f'{n}.node'), 'w') as f:
        f.write(f"addr={a.split('@')[1]}\n")
        f.write('user=root\n')
        f.write('0:ifname=bond0\n')
        f.write(f"0:ip={a.split('@')[1]}\n")
