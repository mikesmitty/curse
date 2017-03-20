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

if [ -f /etc/redhat-release ]; then
    # Add ourselves to the apache group on centos for access to pwauth
    usermod -a -G apache curse
elif [ -f /etc/debian_version ]; then
    # Update the pwauth path in cursed.yaml for debian/ubuntu
    sed -i 's|^pwauth: /usr/bin/|pwauth: /usr/sbin/|' $CURSE_ROOT/etc/cursed.yaml
fi

echo "Starting cursed service"
systemctl start cursed

# Copy the newly-generated CA file to /etc/jinx/ca.crt
sleep 2
pid_count=$(ps aux |grep cursed |grep -vc grep)
if [ "$pid_count" -gt "0" ]; then
    mkdir -p /etc/jinx/ && cp $CURSE_ROOT/etc/cursed.crt /etc/jinx/ca.crt
else
    echo "If using jinx on this server, copy the newly generate curse CA certificate to /etc/jinx/"
    echo "mkdir -p /etc/jinx/"
    echo "cp $CURSE_ROOT/etc/cursed.crt /etc/jinx/ca.crt"
fi
