# SSH
During the imaging process, enable ssh and setup a user with password on the linux image. 

1. Connect Pi to laptop ethernet
1. Boot up Pi
1. In Windows PowerShell, use `arp -a`
    1. Find entry with physical address e4-5f-01-fd-a0-df
    1. Use corresponding IP address (ie. 192.168.137.227)
    1. If the entry does not show up, go to Control Panel > Network and Sharing > Change adapter settings > [right click] Wi-Fi and click properties > sharing > uncheck allow sharing; click ok; open again and re-enable sharing to Ethernet; then reboot the Pi
1. `ssh eriku@192.168.137.227` and enter password configured earlier

# Network File Share
On the Pi, run
```bash
sudo apt update
sudo apt install samba samba-common-bin
```
Add a Samba user (just use same user and password for simplicity)
```bash
sudo smbpasswd -a pi
```
Modify the Samba config
```bash
sudo vi /etc/samba/smb.conf
```
to include the following at the very bottom of the file
```
[trust-cam]
    comment = TrustCam Share
    path = /home/eriku/Pictures
    browsable = yes
    writeable = no
    only guest = no
    create mask = 0777
    directory mask = 0777
    valid users = eriku
```
This will share all the contents of `/home/eriku/Pictures` to a network share called `trust-cam`.

Restart Samba with the changes.
```bash
sudo systemctl restart smbd
```

Then, in Windows file manager, enter the following path:
```
\\192.168.137.227\trust-cam
```
and supply the Samba user credentials when prompted.

### Using TPM

The TPM does not work with recent versions of raspian OS [see here](https://community.infineon.com/t5/Knowledge-Base-Articles/Enabling-amp-testing-Infineon-OPTIGA-TPM-on-Raspberry-Pi-under-Linux/ta-p/623548#.) so I ended up not using it.

Edit `/boot/firmware/config.txt` in vi and add the following lines:
```
# Enable TPM
dtparam=spi=on
dtoverlay=tpm-slb9670,cs=1
```
save changes and reboot
```bash
sudo reboot
```

```bash
sudo apt-get install libtss2-dev tpm2-tools tpm2-abrmd
```

### Image Capture
```bash
sudo apt install libimage-exiftool-perl
```
