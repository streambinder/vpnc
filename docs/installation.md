# Installation

```bash
git clone https://github.com/streambinder/vpnc.git
cd vpnc
make
sudo make install
```

## General configuration

Few libraries are required to let VPNC work properly:

- `libgcrypt` (version: `1.1.90+`)
- `libopenssl` (optional, needed to provide hybrid support)

Configuration data gets read from:

- command-line options
- config file(s) specified on the command line
- `/etc/vpnc/default.conf`, if no config file was given on the command line
- `/etc/vpnc.conf`, if no config file was given on the command line
- output prompt, if a settings can't get loaded from any of those places above

Essential configuration informations (both with key name for specifying option via command line or config file) it currently needs are:

Input option | File option
------------ | ----------------
`--gateway`  | `IPSec gateway`
`--id`       | `IPSec ID`
`--secret`   | `IPSec secret`
`--username` | `Xauth username`
`--password` | `Xauth password`

A sample configuration file is:

```text
IPSec gateway 127.0.0.1
IPSec ID sample-vpn
IPSec secret s4mpl3
Xauth username johndoe
```

Note that all strings start exactly one space after the keyword string, and run to the end of the line. This lets you put any kind of weird character (except CR, LF and NUL) in your strings, but it does mean you can't add comments after a string, or spaces before them.

It may be easier to use the `--print-config` option to generate the config file, and then delete any lines (like a password) that you want to be prompted for.

If you don't know the Group ID and Secret string, ask your administrator. If (s)he declines and refers to the configuration files provided for the vpnclient program, tell him/her that the contents of that files are (though scrambled) not really protected. If you have a working configuration file (`.pcf` file) for the Cisco client then you can use the `pcf2vpnc` utility instead, which will extract most/all of the required information and convert it into a vpnc configuration file.

## Using a modified script

Please note that VPNC itself does not setup routing. You need to do this yourself, or use `--script script.sh` / `Script script.sh` (the first one to pass it as input parameters, the other one as config file value). The default script is `/etc/vpnc/vpnc-script` which sets a default route to the remote network, or if the Concentrator provided split-network settings, these are used to setup routes.

This option is passed to `system()`, so you can use any shell-specials you like. This script gets called tree times:

1. `$reason == pre-init`: this is before VPNC opens the tun device, so you can do what is necessary to ensure that it is available. Note that none of the variables mentioned below is available.
2. `$reason == connect`: this is what used to be "Config Script". The connection is established, but vpnc will not begin forwarding packets until the script finishes.
3. `$reason == disconnect`: This is called just after vpnc received a signal. Note that VPNC will not forward packets anymore while the script is running or thereafter.

Information is passed from VPNC via environment variables:

- `reason`: why this script was called, one of: `pre-init`, `connect`, `disconnect`
- `VPNGATEWAY`: VPN gateway address (always present)
- `TUNDEV`: tunnel device (always present)
- `INTERNAL_IP4_ADDRESS`: address (always present)
- `INTERNAL_IP4_NETMASK`: netmask (often unset)
- `INTERNAL_IP4_DNS`: list of DNS servers
- `INTERNAL_IP4_NBNS`: list of wins servers
- `CISCO_DEF_DOMAIN`: default domain name
- `CISCO_BANNER`: banner from server
- `CISCO_SPLIT_INC`: number of networks in split-network-list
- `CISCO_SPLIT_INC_%d_ADDR`: network address
- `CISCO_SPLIT_INC_%d_MASK`: subnet mask (for example: `255.255.255.0`)
- `CISCO_SPLIT_INC_%d_MASKLEN`: subnet mask length (for example: `24`)
- `CISCO_SPLIT_INC_%d_PROTOCOL`: protocol (often just `0`)
- `CISCO_SPLIT_INC_%d_SPORT`: source port (often just `0`)
- `CISCO_SPLIT_INC_%d_DPORT`: destination port (often just `0`)

Currently `vpnc-script` is not directly configurable from config files. However, a workaround is to use a `wrapper-script` like this, to disable `/etc/resolv.conf` rewriting and setup a custom split-routing:

```bash
#!/bin/sh

# this effectively disables changes to /etc/resolv.conf
INTERNAL_IP4_DNS=

# This sets up split networking regardless
# of the concentrators specifications.
# You can add as many routes as you want,
# but you must set the counter $CISCO_SPLIT_INC
# accordingly
CISCO_SPLIT_INC=1
CISCO_SPLIT_INC_0_ADDR=131.246.89.7
CISCO_SPLIT_INC_0_MASK=255.255.255.255
CISCO_SPLIT_INC_0_MASKLEN=32
CISCO_SPLIT_INC_0_PROTOCOL=0
CISCO_SPLIT_INC_0_SPORT=0
CISCO_SPLIT_INC_0_DPORT=0
```

Store this example script, for example in `/etc/vpnc/custom-script`, do a `chmod +x /etc/vpnc/custom-script` and add `Script /etc/vpnc/custom-script` to your configuration.

### Additional steps to configure hybrid authentication

Input option         | File option
-------------------- | ------------------
`--hybrid`           | `Use Hybrid Auth`
`--ca-file <ca.pem>` | `CA-File <ca.pem>`
`--ca-dir <ca/dir>`  | `CA-Dir <ca/dir>`

Default `CA-Dir` is `/etc/ssl`. A link can also be used like in `/etc/ssl/certs/`.

As the trusted certificate is referenced by the hash of the subject name, the directory has to contain the certificate named like that hash value. As an example, the hash value can be calculated using the following command: `openssl x509 -in <ca_certfile.pem> -noout -hash`
