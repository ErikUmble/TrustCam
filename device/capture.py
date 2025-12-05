#!/usr/bin/env python3
"""
TrustCam Main Script
Captures images periodically and signs them with a private key.
"""

import subprocess
import time
import json
import hashlib
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from PIL import Image
from PIL.ExifTags import TAGS
import piexif
from picamera2 import Picamera2
import io
import rawpy
import os


class TrustCam:
    """System for capturing and signing images from Pi Camera."""
    
    def __init__(self, output_dir="~/Pictures", key_dir="keys"):
        """
        Initialize the camera signing system.
        
        Args:
            output_dir: Directory to save signed images
            key_dir: Directory to store/load cryptographic keys
            use_raw: If True, capture in DNG (raw) format. If False, use PNG.
        """
        self.output_dir = Path(output_dir).expanduser()
        self.key_dir = Path(key_dir).expanduser()
        
        self.output_dir.mkdir(exist_ok=True)
        self.key_dir.mkdir(exist_ok=True)
        
        self.camera = Picamera2()

        self.capture_config = self.camera.create_still_configuration(
            main={"size": (1920, 1080)},
            raw={"size": self.camera.sensor_resolution},  # Full sensor resolution for raw
            buffer_count=2
        )

        self.camera.configure(self.capture_config)
        self.camera.start()
        
        # allow camera to warm up
        time.sleep(2)
        
        # Load or generate keys
        self.private_key, self.public_key = self._load_or_generate_keys()
        
        print("Camera initialized successfully!")
        print(f"Images will be saved to: {self.output_dir.absolute()}")
        print(f"Public key saved to: {self.key_dir / 'public_key.pem'}")
    
    def _load_or_generate_keys(self):
        """
        Load existing keys or generate new ECDSA key pair.
        
        Returns:
            tuple: (private_key, public_key)
        """
        private_key_path = self.key_dir / "private_key.pem"
        public_key_path = self.key_dir / "public_key.pem"
        
        if private_key_path.exists() and public_key_path.exists():
            print("Loading existing keys...")
            
            # Load private key
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Load public key
            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        else:
            
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            with open(private_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            
            with open(public_key_path, "wb") as f:
                f.write(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )
                    
        return private_key, public_key
    
    def sign_hash(self, image_hash):
        """
        Sign the image hash with ECDSA private key.
        
        Args:
            image_hash: Hex-encoded hash string
            
        Returns:
            bytes: Digital signature
        """
        signature = self.private_key.sign(
            image_hash.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def create_metadata(self, signature, image_hash):
        """
        Create metadata dictionary for the signed image.
        
        Args:
            signature: Digital signature bytes
        Returns:
            dict: Metadata dictionary
        """
        # Get public key as PEM string
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        metadata = {
            "version": "1.0",
            "signature": signature.hex(),
            "public_key": public_key_pem,
            "signature_algorithm": "ECDSA-P256",
            "curve": "SECP256R1",
            "image_hash_type": "SHA256",
            "image_hash": image_hash,
        }
        
        return metadata
    
    def capture_and_sign(self):
        """
        Capture an image, sign the pixel/raw data, and save with signature.
        """
        try:
            # Get current timestamp
            timestamp = datetime.utcnow().isoformat() + "Z"
            
            buffers, metadata = self.camera.switch_mode_and_capture_buffers(self.capture_config, ["main", "raw"])
            
            # save jpg and dng
            filename_base = timestamp.replace(":", "-").replace("T", "_").split(".")[0]
            filename_base = os.path.join(self.output_dir, filename_base)
            self.camera.helpers.save(self.camera.helpers.make_image(buffers[0], self.capture_config["main"]), metadata, f"{filename_base}.jpg")
            self.camera.helpers.save_dng(buffers[1], metadata, self.capture_config["raw"], f"{filename_base}.dng")
            
            # open raw image to compute the hash of the image data
            with rawpy.imread(f"{filename_base}.dng") as raw:
                raw_data_from_file = raw.raw_image
                image_hash = hashlib.sha256(raw_data_from_file.tobytes()).hexdigest()
            
            # Sign the hash
            signature = self.sign_hash(image_hash)
            
            # get metadata with signature info
            metadata = self.create_metadata(
                signature=signature, 
                image_hash=image_hash
            )

            # save metadata and hash to exif 
            exiftool_command = [
                "exiftool",
                f"-XMP-et:OriginalImageHash={image_hash}",
                "-XMP-et:OriginalImageHashType=SHA256",
                f"-UserComment={json.dumps(metadata)}",
                "-overwrite_original",
                f"{filename_base}.dng"
            ]
                        
            result = subprocess.run(
                exiftool_command,
                capture_output=True,
                text=True,
                check=True
            )
            print(f"ExifTool Output: {result.stdout.strip()}")

        except subprocess.CalledProcessError as e:
            print(f"Stderr: {e.stderr}")
            print(f"Stdout: {e.stdout}")
            
        except Exception as e:
            import traceback
            traceback.print_exc()
    
    def run(self, interval=5):
        """
        Run the continuous capture loop.
        
        Args:
            interval: Seconds between captures (default: 5)
        """
        print(f"\nStarting continuous capture (every {interval} seconds)")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.capture_and_sign()
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources."""
        if hasattr(self, 'camera'):
            self.camera.stop()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="TrustCam Main Script"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Seconds between captures (default: 5)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="~/Pictures/",
        help="Directory to save images (default: Pictures)"
    )
    parser.add_argument(
        "--key-dir",
        type=str,
        default="keys",
        help="Directory for cryptographic keys (default: keys)"
    )

    
    args = parser.parse_args()
    
    system = TrustCam(
        output_dir=args.output_dir,
        key_dir=args.key_dir,
    )
    
    system.run(interval=args.interval)


if __name__ == "__main__":
    main()