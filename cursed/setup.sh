#!/bin/bash

# Requires:
# openssh
# libcap || libcap2-bin (debian/ubuntu)

CURSE_ROOT="/opt/curse"
CURSE_ALGO="ed25519"

# Create curse system user account
NOLOGIN=$(which nologin)
getent passwd curse >/dev/null || useradd -r -m -d "$CURSE_ROOT" -s $NOLOGIN curse
chmod 700 "$CURSE_ROOT"
chown curse. "$CURSE_ROOT"

# Generate SSH CA keypair
if [ ! -e "$CURSE_ROOT/etc/user_ca" ] || [ ! -e "$CURSE_ROOT/etc/user_ca.pub" ]; then
    echo "Generating $CURSE_ALGO SSH CA certificates..."
    ssh-keygen -q -N "" -t "$CURSE_ALGO" -f "$CURSE_ROOT/etc/user_ca"
    chmod 600 "$CURSE_ROOT/etc/user_ca"
    chmod 644 "$CURSE_ROOT/etc/user_ca.pub"
    echo "$CURSE_ALGO SSH CA keypair generated. Here is the CA PubKey for adding to your servers:"
    echo
    echo
    cat "$CURSE_ROOT/etc/user_ca.pub"
    echo
    echo
    echo "This key can also be found at $CURSE_ROOT/etc/user_ca.pub"
else
    echo "SSH CA keypair already exists. Skipping generation."
fi

# Fix curse permissions
chown -R curse. "$CURSE_ROOT"
/usr/bin/env setcap 'cap_net_bind_service=+ep' /opt/curse/sbin/cursed

echo "Starting cursed service"
systemctl start cursed

# Setup local auth
echo
echo "Enable authentication for local users?"
echo "Note: this requires nginx to be able to read /etc/shadow"
echo
echo -n "Allow nginx to read /etc/shadow [y/N]: "
read shadow

if [ "$shadow" = "y" ]; then
    echo "Setting /etc/shadow permissions for nginx"
    groupadd -f -r shadow && chown :shadow /etc/shadow && chmod g+r /etc/shadow
    if [ ! -f /etc/pam.d/nginx ]; then
        echo -e "auth    required     pam_unix.so\naccount required     pam_unix.so" >/etc/pam.d/nginx
    else
        echo "/etc/pam.d/nginx already exists. Skipping file"
    fi

    ngx_user=$(grep ^user /etc/nginx/nginx.conf |sed -r -e 's/user\s+//' -e 's/\s*;//')
    if [ -n "$ngx_user" ]; then
        echo "Adding nginx user $ngx_user to shadow group"
        usermod -a -G shadow $ngx_user
    else
        echo "Failed to find nginx user. Please add nginx user to shadow group manually: usermod -a -G shadow NGINX_USER"
    fi

    systemctl restart nginx
else
    echo "Skipping local auth configuration"
fi

# Configure nginx
if [ -d /etc/nginx/conf.d ] && [ ! -e /etc/nginx/conf.d/cursed.conf ]; then
    echo "Copying nginx config to /etc/nginx/conf.d/"
    cp /opt/curse/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf
fi
if [ ! -d /etc/nginx/conf.d/ ]; then
    echo "nginx conf.d folder does not exist. You will need to copy the nginx config manually after installing nginx:"
    echo "cp /opt/curse/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf"
fi

pid_count=$(ps aux |grep cursed |grep -vc grep)
if [ "$pid_count" -gt "0" ]; then
    mkdir -p /etc/jinx/ && cp $CURSE_ROOT/etc/cursed.crt /etc/jinx/ca.crt
fi
