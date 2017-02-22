# CURSE: Certificate Utilization for Robust SSH Ephemerality

CURSE is an SSH certificate signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS.

## Demo

![gif](http://i.imgur.com/UtDkYNo.gif)

This software is currently in a beta state, feel free to submit issues on GitHub with any issues encountered.

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 12.04+

Because SSH certificates are a relatively recent feature in OpenSSH, older versions of CentOS unfortunately do not support their use.

Install
-------
These instructions assume the bastion host is hosting the curse daemon. Adjust instructions as necessary if hosting cursed on another server, but for security reasons the reverse proxy and cursed service should always be hosted on the same server at this time.

**CentOS 7**

First, install nginx:

    $ sudo yum install epel-release
    $ sudo yum install nginx

    $ sudo rpm --import https://mirror.go-repo.io/curse/centos/RPM-GPG-KEY-GO-REPO
    $ sudo curl -s https://mirror.go-repo.io/curse/centos/curse-repo.repo | tee /etc/yum.repos.d/curse-repo.repo
    $ sudo yum install curse jinx

After install setup (generates keys and proxy config):
Please note the -a flag in the cp command, the permissions on this config file must be 600 to prevent open access to the curse daemon.

    $ sudo bash /opt/curse/sbin/setup.sh
    $ sudo cp -a /opt/curse/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf

Install/configure your SSL certificates authentication settings for the reverse proxy. Don't forget to set your `server_name` to match your valid SSL certificates as well:

    $ sudo vim /etc/nginx/conf.d/cursed.conf

Once your authentication is configured and certificates in place, restart nginx:

    $ sudo systemctl restart nginx

Copy the jinx config template into place and update the `url` setting to match your SSL certificate FQDN:

    $ sudo cp /etc/jinx/jinx.yaml-example /etc/jinx/jinx.yaml
    $ sudo vim /etc/jinx/jinx.yaml

If all went well you should now be able to request certificates:

    $ jinx
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
* ~~RPM~~/DEB packages for easier installation
* Per-user access ACLs

Maybe Somedays
--------------
* Interactive ssh client for command logging
