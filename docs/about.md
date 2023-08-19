# About

VPNC is a VPN client compatible with Cisco's EasyVPN equipment. It supports IPSec (ESP) with Mode Configuration and Xauth. Supports only shared-secret IPSec authentication with Xauth, AES (256, 192, 128), 3DES, 1DES, MD5, SHA1, DH1/2/5 and IP tunneling. It runs entirely in userspace. Only "Universal TUN/TAP device driver support" is needed in kernel.

## Development status

This repository has been forked to follow the work started originally by Maurice Massar. For more information about that, please, point to [VPNC original web page](http://www.unix-ag.uni-kl.de/~massar/vpnc/).

As stated in `vpnc-devel` mailing-list ([vpnc-devel@2017-November](http://lists.unix-ag.uni-kl.de/pipermail/vpnc-devel/2017-November/004233.html)), this repository hasn't been started to start working actively on this project, but to passively merge security patches, fixes and features additions explicitly requested by the community.

**This means I won't even consider issues such as _"Please, implement this"_, or _"Look at that, maybe you can find ideas and fixes"_, but I will if requested via explicit PRs and/or issues pointing to a (or many) specific patch**.
