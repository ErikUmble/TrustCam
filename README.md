# TrustCam
Image verification and authentication for security cameras.

> [!WARNING]
> This is a prototype verification system and is not secure against hardware cryptography attacks. For a production-ready version, move the signature generation to a circuit within the image sensor itself (sign image data before OS can access it) and wrap the image sensor with a tamper responent mechanism that prevents the camera from authenticating if any tampering is detected. Examples include resetting or nullifying the signing key, or leaving a permenant visible change on the camera which a human can observe. 


# Installation
```bash
sudo apt install zbar-tools libzbar-dev
sudo apt install python3-zbar
pip install -r ui/requirements.txt
```

# Run UI
```bash
python ui/verification_ui.py
```
