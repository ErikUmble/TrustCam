#!/usr/bin/env python3
"""
Security Camera Image Verification Prototype
A complete PySide6 application for verifying signed images from security cameras.
"""

import json
import subprocess
import sys
import secrets
import random
from pathlib import Path
from io import BytesIO
import cv2
from PIL import Image
from pyzbar import pyzbar
import rawpy

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog, QSplitter
)
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtCore import Qt, QSize

from PIL import Image
import qrcode
import hashlib
import sys
from pathlib import Path
from PIL import Image
from PIL import PngImagePlugin
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class DragDropImageLabel(QLabel):
    """Custom QLabel that accepts drag and drop of image files."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.parent_window = parent
    
    def dragEnterEvent(self, event):
        """Accept drag events with file URLs."""
        if event.mimeData().hasUrls():
            # Check if at least one URL is a file
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    event.acceptProposedAction()
                    return
    
    def dragMoveEvent(self, event):
        """Accept drag move events."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        """Handle dropped files."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].isLocalFile():
                filepath = urls[0].toLocalFile()
                if self.parent_window:
                    self.parent_window.handle_chosen_image(filepath)
                event.acceptProposedAction()


class VerificationUI(QMainWindow):
    """Main application window for security camera image verification."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Camera Image Verification")
        self.setMinimumSize(1200, 700)
        
        # Global state variables
        self.current_image_path = None
        self.authentication_token = None
        self.camera_public_key = None
        self.is_camera_authorized = False
        self.qr_pixmap = None
        
        # Initialize UI
        self.init_ui()
        
        # Generate initial QR code
        self.generate_and_display_qr()
    
    def init_ui(self):
        """Initialize the user interface with all components."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        # Create splitter for resizable columns
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left column (4/5 width) - Image display area
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        self.image_label = DragDropImageLabel(self)
        self.image_label.setText("Drop image here or click 'Select Image'")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("""
            QLabel {
                background-color: #2b2b2b;
                color: #888;
                font-size: 16px;
                border: 2px dashed #555;
            }
        """)
        self.image_label.setMinimumSize(600, 400)
        self.image_label.setScaledContents(False)
        
        left_layout.addWidget(self.image_label)
        
        # Right column (1/5 width) - Control panel
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setSpacing(15)
        
        # Instructions section
        instructions_label = QLabel("<b>Instructions</b>")
        instructions_label.setStyleSheet("font-size: 14px; color: #2196F3;")
        right_layout.addWidget(instructions_label)
        
        self.instructions_text = QTextEdit()
        self.instructions_text.setReadOnly(True)
        self.instructions_text.setMaximumHeight(200)
        self.instructions_text.setStyleSheet("""
            QTextEdit {
                background-color: #f5f5f5;
                border: 1px solid #ccc;
                padding: 8px;
                font-size: 12px;
            }
        """)
        self.instructions_text.setHtml("""
            <p><b>Step 1: Camera Authorization</b><br>
            Scan the QR code displayed in the main area with your security camera to authorize it.</p>
            <p><b>Step 2: Upload Authorization Image</b><br>
            Drag and drop (or load) the signed image containing the QR code to register the camera's public key.</p>
            <p><b>Step 3: Verify Images</b><br>
            Drag and drop (or load) any signed image from the authorized camera to verify its authenticity.</p>
        """)
        right_layout.addWidget(self.instructions_text)
        
        # QR Code section
        qr_label = QLabel("<b>Authorization QR Code</b>")
        qr_label.setStyleSheet("font-size: 14px; color: #2196F3;")
        right_layout.addWidget(qr_label)
        
        # Control panel section
        control_label = QLabel("<b>Control Panel</b>")
        control_label.setStyleSheet("font-size: 14px; color: #2196F3; margin-top: 10px;")
        right_layout.addWidget(control_label)
        
        # File path display
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("No file selected")
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #f9f9f9;
            }
        """)
        right_layout.addWidget(self.file_path_input)
        
        # Select image button
        select_btn = QPushButton("Select Image")
        select_btn.clicked.connect(self.select_image_file)
        select_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        right_layout.addWidget(select_btn)
        
        # Status section
        status_label = QLabel("<b>Status</b>")
        status_label.setStyleSheet("font-size: 14px; color: #2196F3; margin-top: 10px;")
        right_layout.addWidget(status_label)
        
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(150)
        self.status_text.setStyleSheet("""
            QTextEdit {
                background-color: #fff3cd;
                border: 1px solid #ffc107;
                padding: 8px;
                font-size: 12px;
                font-family: monospace;
            }
        """)
        self.status_text.setHtml("<p style='color: #856404;'><b>Starting authentication process...</b></p>")
        right_layout.addWidget(self.status_text)
        
        # Add stretch to push everything to the top
        right_layout.addStretch()
        
        # Set splitter sizes (80% left, 20% right)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([800, 300])
        
    def generate_and_display_qr(self):
        """Generate a random authorization token and display it as a QR code."""
        # Generate a random 128-bit token as hex string
        self.authentication_token = f"AUTH:{secrets.token_hex(16)}"
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.authentication_token)
        qr.make(fit=True)
        
        # Generate QR code image
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Convert PIL image to QPixmap
        self.qr_pixmap = self.pil_to_qpixmap(qr_image)
        
        # Display QR code (scaled to fit)
        scaled_pixmap = self.qr_pixmap.scaled(
            self.image_label.size(),
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )
        self.image_label.setPixmap(scaled_pixmap)
        
        # Update status
        self.update_status(
            "Please scan QR code with your security camera and upload the picture of it to authenticate.",
            "#856404"
        )
        
        # Reset authorization state
        self.camera_public_key = None
        
    def select_image_file(self):
        """Open file dialog to select an image file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image File",
            "",
            "Image Files (*.dng);;All Files (*)"
        )
        
        if file_path:
            self.handle_chosen_image(file_path)
            
    def handle_chosen_image(self, file_path):
        self.current_image_path = file_path
        self.file_path_input.setText(file_path)
        self.load_image_and_verify(file_path)
    
    def load_image_and_verify(self, filepath):
        """
        Load an image and perform verification workflow.
        
        Args:
            filepath: Path to the image file
        """
        try:
            # Load and display image
            image = Image.open(filepath)
            pixmap = self.pil_to_qpixmap(image)
            
            # Scale to fit the display area while maintaining aspect ratio
            scaled_pixmap = pixmap.scaled(
                self.image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            self.image_label.setPixmap(scaled_pixmap)

        except Exception as e:
            self.update_status(
                f"❌ <b>Error loading image</b><br><br>",
                "#721c24",
                "#f8d7da"
            )
            print(e)
        
        try:            
            image_hash = self.calculate_image_hash(filepath)
            
            # Extract metadata (placeholder)
            metadata = self.extract_metadata(filepath)
            stored_image_hash = metadata.get("image_hash")
            signature = metadata.get("signature")
            public_key_pem= metadata.get("public_key")
            
            # Parse the public key from PEM format
            if public_key_pem:
                try:
                    public_key = serialization.load_pem_public_key(
                        public_key_pem.encode('utf-8'),
                        backend=default_backend()
                    )
                except Exception as e:
                    self.update_status(
                        "This image does not appear to be signed by a TrustCam device.",
                        "#721c24",
                        "#f8d7da"
                    )
                    return
            else:
                self.update_status(
                    "This image does not appear to be signed by a TrustCam device.",
                    "#721c24",
                    "#f8d7da"
                )
                return
            
            # check for authentication image if unauthenticated
            if self.camera_public_key is None:
                if self.attempt_authentication(filepath, public_key_pem):
                    self.update_status(
                        f"✅ <b>Camera Authorized Successfully!</b><br><br>"
                        f"You can now verify images from this camera.",
                        "#155724",
                        "#d4edda"
                    )
                    return
                else:
                    self.update_status(
                        "❌ <b>Authorization Failed</b><br><br>"
                        "The QR code was not found in this image. "
                        "Please ensure you captured the QR code displayed in the main area.",
                        "#856404",
                        "#fff3cd"
                    )
                    return
                
            # tampering if image hash changed
            if image_hash != stored_image_hash:
                self.update_status(
                    f"❌ <b>Verification FAILED</b><br><br>"
                    f"This image may have been modified.",
                    "#721c24",
                    "#f8d7da"
                )
                return
            
            # unauthenticated or tampered camera if public key mismatch
            if public_key_pem != self.camera_public_key:
                self.update_status(
                    f"❌ <b>Verification FAILED</b><br><br>"
                    f"This image was not signed by the authenticated camera, or the camera has been tampered with since capturing this image.",
                    "#721c24",
                    "#f8d7da"
                )
                return

            # finally, check signature validity
            is_valid = self.verify_signature(image_hash, signature, public_key)
            
            
            # Display results
            if is_valid:
                self.update_status(
                    f"✅ <b>Verification SUCCESS</b><br><br>"
                    f"Signature: Valid ✓<br>"
                    f"Camera: Authorized ✓<br>"
                    f"This image is very likely captured by the authenticated camera.",
                    "#155724",
                    "#d4edda"
                )
            else:
                self.update_status(
                    f"❌ <b>Verification FAILED</b><br><br>"
                    f"Image Hash: {image_hash}<br>"
                    f"Signature: Invalid ✗<br>"
                    f"Public Key: {public_key[:16]}...<br><br>"
                    f"This image may have been tampered with or is not from a valid source.",
                    "#721c24",
                    "#f8d7da"
                )
            
        except Exception as e:
            self.update_status(
                f"❌ <b>Error verifying image</b><br><br>",
                "#721c24",
                "#f8d7da"
            )
            print(e)
    
    def attempt_authentication(self, filepath, public_key):
        """
        Attempt to authenticate a camera by verifying the QR code in the image.
        
        Args:
            filepath: Path to the authentication image
            public_key: Public key extracted from the image
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        qr_detected = self.extract_qr_data(filepath)
        
        if qr_detected and qr_detected == self.authentication_token:
            self.camera_public_key = public_key
            return True
        print(f"QR code detected: {qr_detected}, expected: {self.authentication_token}")
        return False
    
    def extract_qr_data(self, filepath):
        """
        Placeholder function to detect and decode QR code in an image.
        
        Args:
            filepath: Path to the image file
            
        Returns:
            str: Decoded QR code content or None
        """
        image = cv2.imread(filepath)

        detector = cv2.QRCodeDetector()
        data, vertices_array, _ = detector.detectAndDecode(image)

        if vertices_array is None or len(vertices_array) == 0:
            # no QR code detected
            return None  
        
        # crop to QR code area
        y_min = min(vertices_array[0][:,1])
        y_max = max(vertices_array[0][:,1])
        x_min = min(vertices_array[0][:,0])
        x_max = max(vertices_array[0][:,0])

        # pad bounds by 10% to include white border
        y_pad = int((y_max - y_min) * 0.1)
        x_pad = int((x_max - x_min) * 0.1)
        y_min = max(0, y_min - y_pad)
        y_max = min(image.shape[0], y_max + y_pad)
        x_min = max(0, x_min - x_pad)
        x_max = min(image.shape[1], x_max + x_pad)

        image = image[y_min:y_max, x_min:x_max]
        #image = cv2.GaussianBlur(image, (25, 25), 0)  # apply Gaussian blur to remove noise from screen pixels
        data = pyzbar.decode(Image.fromarray(image))
        if data:
            return data[0].data.decode('utf-8')
        
        return None
    
    def calculate_image_hash(self, filepath):
        """
        Placeholder function to calculate cryptographic hash of an image.
        
        Args:
            filepath: Path to the image file
            
        Returns:
            str: Simulated hash string
        """
        image_hash = ""
        # open raw image to compute the hash of the image data
        with rawpy.imread(f"{filepath}.dng") as raw:
            raw_data_from_file = raw.raw_image
            image_hash = hashlib.sha256(raw_data_from_file.tobytes()).hexdigest()
        return image_hash
            
    
    def extract_metadata(self, filepath):
        """
        Placeholder function to extract signature and public key from image metadata.
        
        Args:
            filepath: Path to the image file
            
        Returns:
            dict: Dictionary containing 'signature' and 'public_key'
        """
        try:
            exiftool_command = [
                "exiftool",
                "-XMP-et:OriginalImageHash",
                "-XMP-et:OriginalImageHashType",
                "-UserComment",
                "-j",
                filepath
            ]
            
            result = subprocess.run(
                exiftool_command,
                capture_output=True,
                text=True,
                check=True
            )
            
            # ExifTool returns a JSON array of one object
            exifdata = json.loads(result.stdout)
            stored_hash = exifdata[0].get("OriginalImageHash", "")
            hash_type = exifdata[0].get("OriginalImageHashType", "")
            user_comment = exifdata[0].get("UserComment", "{}")
            
            # Parse the UserComment JSON
            metadata = json.loads(user_comment)
            metadata["image_hash"] = stored_hash
            metadata["hash_type"] = hash_type
            
            return metadata
            
        except subprocess.CalledProcessError as e:
            print(f"ExifTool error: {e.stderr}")
            return {}
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            return {}
        except Exception as e:
            print(f"Error extracting metadata: {e}")
            return {}
    
    def verify_signature(self, image_hash, signature_hex, public_key):
        """
        Verify the ECDSA signature on an image hash.
        
        Args:
            public_key: Public key object
            image_hash: Hex-encoded hash string
            signature_hex: Hex-encoded signature string
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            if not image_hash or not signature_hex or not public_key:
                return False
            signature = bytes.fromhex(signature_hex)
            
            public_key.verify(
                signature,
                image_hash.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Error during verification: {e}")
            return False
    
    def update_status(self, message, text_color="#000000", bg_color="#ffffff"):
        """
        Update the status display with a message.
        
        Args:
            message: HTML formatted status message
            text_color: Text color (hex)
            bg_color: Background color (hex)
        """
        self.status_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {bg_color};
                border: 1px solid {text_color};
                padding: 8px;
                font-size: 12px;
                color: {text_color};
            }}
        """)
        self.status_text.setHtml(f"<div style='color: {text_color};'>{message}</div>")
    
    def pil_to_qpixmap(self, pil_image):
        """
        Convert a PIL Image to QPixmap.
        
        Args:
            pil_image: PIL Image object
            
        Returns:
            QPixmap: Converted pixmap
        """
        # Convert PIL image to RGB if necessary
        if pil_image.mode != "RGB":
            pil_image = pil_image.convert("RGB")
        
        # Convert to bytes
        buffer = BytesIO()
        pil_image.save(buffer, format="PNG")
        buffer.seek(0)
        
        # Create QPixmap from bytes
        qimage = QImage()
        qimage.loadFromData(buffer.read())
        
        return QPixmap.fromImage(qimage)
    
    def resizeEvent(self, event):
        """Handle window resize to scale image appropriately."""
        super().resizeEvent(event)
        
        # Re-scale the current image/QR code if one is displayed
        if self.image_label.pixmap() and not self.image_label.pixmap().isNull():
            # If we're showing the QR code and not authorized yet, rescale it
            if not self.is_camera_authorized and self.qr_pixmap:
                scaled_pixmap = self.qr_pixmap.scaled(
                    self.image_label.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
                self.image_label.setPixmap(scaled_pixmap)


def main():
    """Main entry point for the application."""
    app = QApplication(sys.argv)
    
    app.setStyle("Fusion")
    window = VerificationUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()