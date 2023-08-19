# FAQ

## Use the client with Nortel Contivity

Matt Chapman (`matthewc@cse.unsw.edu.au`) got vpnc working with a Nortel Contivity VPN concentrator. According to him, the differences are:

- The group name and password are pre-transformed:

  ```
  key_id = SHA1(group_name)
  shared_key = HMAC_SHA1(group_name, SHA1(group_password))
  ```

- The XAUTH implementation follows `draft-ietf-ipsec-isakmp-xauth-02.txt` (whereas CISCO uses a later version). Specifically:

  - the encoding of the proposal is not defined in that spec, and Nortel does it differently;
  - the `XAUTH` attributes have different numerical values (which overlap with `Mode-Config`);
  - success/failure are encoded as `Mode-Config` message types 5/6 (or sometimes as an `ISAKMP` notify?) rather than in an attribute;
  - the concentrator always sends `0` in `XAUTH_TYPE` and the client may have to return a different value (`xauth-02` is not clear on whether this is allowed, it is not clarified until `xauth-05`). In my case I'm using an `ActivCard` token for which I have to specify 5 (SecurID).

- `Mode-Config` is done as a push, i.e. the server sends `SET`, instead of a pull.

- The concentrator wants to be the initiator in phase 2 quick mode, so we have to support being a responder.

Thus the changes are fairly intrusive - phase 1 is common but `XAUTH`/`Mode-Config`/phase 2 diverge.

According to Zingo Andersen, `NORTELVPN_XAUTHTYPE_AS_REQUEST` has to be set and this patch applied:

```
#ifdef NORTELVPN_XAUTHTYPE_AS_REQUEST
    if (ap->af != isakmp_attr_16 || !(ap->u.attr_16 == 0 || ap->u.attr_16 == 5))
        reject = ISAKMP_N_ATTRIBUTES_NOT_SUPPORTED;
    xauth_type_requested = ap->u.attr_16;
#else
    if (ap->af != isakmp_attr_16 || ap->u.attr_16 != 0)
        reject = ISAKMP_N_ATTRIBUTES_NOT_SUPPORTED;
#endif
```

## Setting up VPNC on Windows Vista (64 bit)

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

```text
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

## Suddenly client stops without any specific reason

The DHCP leases are very short intervals and on each renew the DHCP client overwrites things like `/etc/resolv.conf` and maybe the default route To solve the issue, fix your `dhcpclient`: on _Debian_ it can be done by installing and using `resolvconf` to modify that file instead of modifying it directly.
