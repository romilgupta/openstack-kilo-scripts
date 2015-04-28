====================================================================
Openstack with Opendaylight Installation script for Ubuntu 14.04 LTS
====================================================================

Single Node Openstack Juno :
--------------------------

  Operating System : Ubuntu14.04 LTS

  NIC's::

    Eth0: Public Network/Management Network
    Eth1: Data Network

Download the Openstack-ODL-Script::

  sudo -i # Scripts need Root user privileges
  git clone https://github.com/romilgupta/Openstack-ODL-Script.git
  cd Openstack-ODL-Script
  
Run ``python install_openstack.py``

Script will prompt you to enter following inputs::

  raw_input("Management Interface IP: ")
  raw_input("Data Interface IP: ")
  raw_input("OpenDaylight Controller IP: ")
  raw_input("Offline Mode True|False: ") # Provide False when you are runnning it first time.

The script will install following components of openstack and configure them::

  Keystone
  Glance
  Neutron(neutron-server with Opendaylight, dhcp-agent, l3-agent)
  Openvswitch
  Nova(nova-api nova-cert nova-scheduler nova-conductor novnc nova-consoleauth nova-novncproxy, nova-compute)
  Dashboard

Source authetication file for CLI ``source adminrc``

Horizon::
  
  Login into horizon http://<Mgmt_Interface_IP>/horizon  Username:admin  Password:password
  
Download Cirros Images::

  http://cloudhyd.com/openstack/images/images.html
