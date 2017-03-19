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

# Fix curse directory permissions
chown -R curse. "$CURSE_ROOT"

# Setup local auth
echo
echo
echo "Enable authentication for local users?"
echo "Note: this requires nginx to be able to read /etc/shadow"
echo
echo -n "Allow nginx to read /etc/shadow [y/N]: "
read shadow

if [ "$shadow" = "y" ]; then
    echo "Setting /etc/shadow permissions for nginx"
    groupadd -f -r shadow && chown :shadow /etc/shadow && chmod g+r /etc/shadow

    ngx_user=$(grep -oP '(?<=user\s)[^;\s]+' /etc/nginx/nginx.conf)
    if [ -z "$ngx_user" ]; then
        echo "Failed to find nginx user. Please add nginx user to shadow group manually: usermod -a -G shadow NGINX_USER"
    else
        echo "Adding nginx user $ngx_user to shadow group"
        usermod -a -G shadow $ngx_user
    fi
else
    echo "Skipping local auth configuration"
fi
