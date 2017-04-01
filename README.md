# CURSE

CURSE is an SSH certificate signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS.

## Demo

![gif](http://i.imgur.com/UtDkYNo.gif)

This software is currently in a beta state, feel free to submit issues on GitHub with any suggestions for improvement/feature requests or issues encountered.

Table of Contents
-----------------

* [Requirements](#requirements)
* [Install](#install)
  * [Ubuntu/Debian](#ubuntudebian)
  * [CentOS](#centos)
* [TODO List](#todo)

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 14.04+ (Destination servers)
* Ubuntu 15.10+ (Server running CURSE daemon)
* Debian 7+ (Destination servers)
* Debian 8+ (Server running CURSE daemon)

Because SSH certificates are a relatively recent feature in OpenSSH, older versions of CentOS unfortunately do not support their use.

Install
-------
These instructions assume the bastion host is hosting the curse daemon. Adjust instructions as necessary if hosting cursed on another server.

### Ubuntu/Debian

**Ubuntu 15.10+/Debian 8+**

First, install the debian repo and GPG key:

    $ sudo sh -c 'echo "deb http://mirror.go-repo.io/curse/deb/ curse main" >/etc/apt/sources.list.d/curse.list'
    $ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 0732065B92735F2F

Update and install pwauth, curse and jinx:

    $ sudo apt-get update && sudo apt-get install curse jinx pwauth

Run the curse post-install setup script

    $ sudo bash /opt/curse/sbin/setup.sh

This will output your CA public key to be added to destination servers, and setup the curse daemon for running.

If all went well you should now be able to request certificates:

    $ jinx echo test
    $ ssh-keygen -Lf ~/.ssh/id_jinx-cert.pub

Now, all that is left is to add the CA public key on the servers you want to connect to:

Add `TrustedUserCAKeys /etc/ssh/cas.pub` to `/etc/ssh/sshd_config` on your destination servers and
Put the contents of `/opt/curse/etc/user_ca.pub` into your /etc/ssh/cas.pub on the destination server.

Netflix recommends generating several CA keypairs and storing the private keys of all but one offline, in order to simplify CA key rotation. If you choose to do this you will want to also add the pubkeys of all of your CA keypairs to the `/etc/ssh/cas.pub` file at this time as well.

### CentOS

**CentOS 7**

First, install pwauth, curse, and jinx:

    $ sudo rpm --import https://mirror.go-repo.io/curse/centos/RPM-GPG-KEY-GO-REPO
    $ sudo curl -s https://mirror.go-repo.io/curse/centos/curse-repo.repo | tee /etc/yum.repos.d/curse-repo.repo
    $ sudo yum install curse jinx pwauth

Run the curse post-install setup script

    $ sudo bash /opt/curse/sbin/setup.sh

This will output your CA public key to be added to destination servers, and setup the curse daemon for running.

If all went well you should now be able to request certificates:

    $ jinx echo test
    $ ssh-keygen -Lf ~/.ssh/id_jinx-cert.pub

Now, all that is left is to add the CA public key on the servers you want to connect to:

Add `TrustedUserCAKeys /etc/ssh/cas.pub` to `/etc/ssh/sshd_config` and
Put the contents of `/opt/curse/etc/user_ca.pub` into your /etc/ssh/cas.pub on the destination server.

Netflix recommends generating several CA keypairs and storing the private keys of all but one offline, in order to simplify CA key rotation. If you choose to do this you will want to also add the pubkeys of all of your CA keypairs to the `/etc/ssh/cas.pub` file at this time as well.

TODO
----
* ~~Authentication~~
* ~~Document Authentication Setup~~
* ~~SSL support~~
* ~~Add support for maximum pubkey ages in daemon~~
* ~~Client app~~
* ~~More configuration options~~
* ~~Add support for maximum pubkey ages in client and automatic key regeneration~~
* ~~Add support for key algorithm enforcement/auto-key-generation~~
* ~~RPM/DEB packages for easier installation~~
* Per-user access ACLs

Maybe Someday
-------------
* Interactive ssh client for command logging
