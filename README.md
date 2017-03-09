# CURSE

CURSE is an SSH certificate signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS.

## Demo

![gif](http://i.imgur.com/UtDkYNo.gif)

This software is currently in a beta state, feel free to submit issues on GitHub with any suggestions for improvement/feature requests or issues encountered.

Table of Contents
-----------------

* [Requirements](#requirements)
* [Install](#install)
  * [Ubuntu 15.10+](#ubuntu-1510)
  * [CentOS 7](#centos-7)
* [TODO List](#todo)

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 14.04+ (Destination servers)
* Ubuntu 15.10+ (Server running CURSE daemon)

Because SSH certificates are a relatively recent feature in OpenSSH, older versions of CentOS unfortunately do not support their use.

Install
-------
These instructions assume the bastion host is hosting the curse daemon. Adjust instructions as necessary if hosting cursed on another server, but for security reasons the reverse proxy and cursed service should always be hosted on the same server unless you have valid SSL certificates for both the reverse proxy and CURSE daemon, and have the `proxy_ssl_verify` setting enabled in nginx.

###Ubuntu 15.10+

First, install the debian repo and GPG key:

    $ sudo sh -c 'echo "deb http://mirror.go-repo.io/curse/deb/ curse main" >/etc/apt/sources.list.d/curse.list'
    $ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 0732065B92735F2F

Update and install nginx, curse and jinx:

    $ sudo apt-get update && sudo apt-get install curse jinx nginx

Run the curse SSH CA keypair/SSL certificate generation script:

    $ sudo bash /opt/curse/sbin/setup.sh

This will output your CA public key to be added to destination servers, and helpful nginx setup commands.

Next, copy the nginx client SSL certificates to the nginx folder, as well as the curse nginx config:

    $ sudo cp -a /opt/curse/etc/cursed-client.{key,crt} /opt/curse/etc/cursed-ca_cert.crt /etc/nginx/
    $ sudo cp -a /opt/curse/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf

At this time, you will want to make sure you have a valid SSL cert ready for your nginx server (from Let's Encrypt or any other valid certificate authority).  
Edit the nginx config to update your `server_name` setting to match your SSL certificate FQDN, configure the valid SSL certs you got from your certificate authority (`/etc/nginx/cert.pem` and `/etc/nginx/key.pem` by default) as well as configure your authentication settings.  
If using basic authentication, you'll need to install `apache2-utils` to get the htpasswd tool, and create your htpasswd file at `/etc/nginx/htpasswd`.

    $ sudo vim /etc/nginx/conf.d/cursed.conf

Once your authentication is configured and certificates in place, restart nginx:

    $ sudo systemctl restart nginx

Update the `url` setting to match your SSL certificate FQDN in the jinx config (and edit any settings you would like to change):

    $ sudo vim /etc/jinx/jinx.yaml

If all went well you should now be able to request certificates:

    $ jinx echo test
    $ ssh-keygen -Lf ~/.ssh/id_jinx-cert.pub

Now, all that is left is to add the CA public key on the servers you want to connect to:

Add `TrustedUserCAKeys /etc/ssh/cas.pub` to `/etc/ssh/sshd_config` on your destination servers and
Put the contents of `/opt/curse/etc/user_ca.pub` into your /etc/ssh/cas.pub on the destination server.

Netflix recommends generating several CA keypairs and storing the private keys of all but one offline, in order to simplify CA key rotation. If you choose to do this you will want to also add the pubkeys of all of your CA keypairs to the `/etc/ssh/cas.pub` file at this time as well.

###CentOS 7

**NOTICE**: If upgrading from CURSE 0.7 you will need to do some manual cleanup after installing the rpm.  
Versions 0.8+ use TLS mutual authentication between the reverse proxy and the curse daemon, and no longer support basic auth which was used in 0.7.
* After installing the new curse rpm, remove the old curse daemon SSL certificate/key: `mv /opt/curse/etc/server.key{,.old}` `mv /opt/curse/etc/server.crt{,.old}`
* Run `/opt/curse/sbin/setup.sh` again to generate the mutual auth certificates (if you have not yet removed the old server.key and server.crt, this will not work properly)
* Import your nginx customizations to (and update `server_name` field in) the new template file: `/opt/curse/etc/cursed.conf-nginx` and copy it to `/etc/nginx/conf.d/`
* Reload nginx to use the new config

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

Maybe Somedays
--------------
* Interactive ssh client for command logging
