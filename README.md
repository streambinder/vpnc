# VPNC

## What is it

VPNC is a VPN client compatible with Cisco's EasyVPN equipment. It supports IPSec (ESP) with Mode Configuration and Xauth. Supports only shared-secret IPSec authentication with Xauth, AES (256, 192, 128), 3DES, 1DES, MD5, SHA1, DH1/2/5 and IP tunneling. It runs entirely in userspace. Only "Universal TUN/TAP device driver support" is needed in kernel.

### Development status

This repository has been forked to follow works started originally by Maurice Massar. For more informations about that, please, point to [VPNC original web page](http://www.unix-ag.uni-kl.de/~massar/vpnc/).

As stated in `vpnc-devel` mailing-list ([vpnc-devel@2017-November](http://lists.unix-ag.uni-kl.de/pipermail/vpnc-devel/2017-November/004233.html)), this repository hasn't been started to start working actively on this project, but to passively merge security patches, fixes and features additions (that haven't been included in Massar's original project due to its maintenance maintenance) explicitly requested by the community.

**This means I won't even consider issues such as `Please, implement this`, or `Look at that, maybe you can find ideas and fixes`, but I will if requested via explicit PRs and/or issues pointing to a (or many) specific patch**.

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

```
# This is a sample configuration file.
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

Variable                      | Meaning
----------------------------- | -----------------------------------------------------------------------
`reason`                      | Why this script was called, one of: `pre-init`, `connect`, `disconnect`
`VPNGATEWAY`                  | VPN gateway address (always present)
`TUNDEV`                      | Tunnel device (always present)
`INTERNAL_IP4_ADDRESS`        | Address (always present)
`INTERNAL_IP4_NETMASK`        | Netmask (often unset)
`INTERNAL_IP4_DNS`            | List of DNS servers
`INTERNAL_IP4_NBNS`           | List of wins servers
`CISCO_DEF_DOMAIN`            | Default domain name
`CISCO_BANNER`                | Banner from server
`CISCO_SPLIT_INC`             | Number of networks in split-network-list
`CISCO_SPLIT_INC_%d_ADDR`     | Network address
`CISCO_SPLIT_INC_%d_MASK`     | Subnet mask (for example: `255.255.255.0`)
`CISCO_SPLIT_INC_%d_MASKLEN`  | Subnet mask length (for example: `24`)
`CISCO_SPLIT_INC_%d_PROTOCOL` | Protocol (often just `0`)
`CISCO_SPLIT_INC_%d_SPORT`    | Source port (often just `0`)
`CISCO_SPLIT_INC_%d_DPORT`    | destination port (often just `0`)

Currently `vpnc-script` is not directly configurable from config files. However, a workaround is to use a `wrapper-script` like this, to disable `/etc/resolv.conf` rewriting and setup a custom split-routing:

```
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

Input option                               | File option
------------------------------------------ | ----------------------------------------
`--hybrid`                                 | `Use Hybrid Auth`
`--ca-file <root_certificate.pem>`         | `CA-File <root_certificate.pem>`
`--ca-dir <trusted_certificate_directory>` | `CA-Dir <trusted_certificate_directory>`

Default `CA-Dir` is `/etc/ssl`. A link can also be used like in `/etc/ssl/certs/`.

As the trusted certificate is referenced by the hash of the subject name, the directory has to contain the certificate named like that hash value. As an example, the hash value can be calculated using the following command: `openssl x509 -in <ca_certfile.pem> -noout -hash`

### Setting up VPNC on Windows Vista (64 bit)

1. Install `cygwin`: follow steps at [cygwin.com](http://www.cygwin.com/)
2. Make sure you install the development options for `cygwin` to give you access to `make`, `gcc`, and all the other develpment libraries
3. Make sure you install `libgcrypt` for `cygwin` as it is needed in the `make` procedure
4. Modify the `bash.exe` to run as administrator or you will have privilege issues later, this is done on the properties tab of the executable in `C:/cygwin/bin`
5. Download the latest VPNC tarball
6. Unzip and explode the tarball
7. Modify `tap-win32.h` to change `#define TAP_COMPONENT_ID "tap0801"` to `#define TAP_COMPONENT_ID "tap0901"` (not sure if this is always necessary, but at least once it has been needed)
8. `make`
9. Download [OpenVPN](http://openvpn.net/download.html). It has been tested with success on version `2.1_rc4`
10. Just install `TAP-Win32 Adapter V9`
11. Go to _Control Panel_, and then _Network Connections_ and rename the TAP devic to `my-tap`
12. Use a `default.conf` built like this:

  ```
  IPSec gateway YOURGATEWAY
  IPSec ID YOURID
  IPSec obfuscated secret YOURREALYLONGHEXVALUE (you can use your clear
  text password here if you remove obfuscated)
  Xauth username YOURUSERNAME
  Xauth password YOURPASSWORD
  Interface name my-tap
  Interface mode tap
  Local Port 0
  ```

## Known problems

In some

Problem      | _In some environments it may happen that stuff works for a while and then stops working._
------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------
**Reason**   | The DHCP leases are very short intervals and on each renew the DHCP client overwrites things like `/etc/resolv.conf` and maybe the default route.
**Solution** | Fix your `dhcpclient`: on _Debian_ that problem can be fixed by installing and using `resolvconf` to modify that file instead of modifying it directly.
