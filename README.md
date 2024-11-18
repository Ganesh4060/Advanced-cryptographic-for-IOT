# Advanced-cryptographic-for-IOT

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
import os
import binascii

# Function definitions
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def aes_encrypt(aes_key, plaintext):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Generate HMAC for integrity
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    hmac.update(iv + ciphertext)
    tag = hmac.finalize()
    
    return iv, ciphertext, tag

def aes_decrypt(aes_key, iv, ciphertext, tag):
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    hmac.update(iv + ciphertext)
    try:
        hmac.verify(tag)  # Raises InvalidSignature if verification fails
    except Exception as e:
        raise ValueError("Integrity check failed") from e
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_text

def perform_key_exchange():
    client_private_key, client_public_key = generate_ecc_key_pair()
    server_private_key, server_public_key = generate_ecc_key_pair()

    client_shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    server_shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

    # Derive AES key from the shared secret on both sides
    client_aes_key = derive_aes_key(client_shared_secret)
    server_aes_key = derive_aes_key(server_shared_secret)
    
    # Confirm both sides derived the same key
    assert client_aes_key == server_aes_key, "Key exchange failed!"
    return client_aes_key

def encrypt_image(aes_key, image_path):
    # Read the image as binary data
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()
    
    # Encrypt the image data
    iv, ciphertext, tag = aes_encrypt(aes_key, image_data)
    return iv, ciphertext, tag

def decrypt_image(aes_key, iv, ciphertext, tag, output_path):
    # Decrypt the image data
    decrypted_data = aes_decrypt(aes_key, iv, ciphertext, tag)
    
    # Write the decrypted data back to an image file
    with open(output_path, 'wb') as output_file:
        output_file.write(decrypted_data)
    print(f"Image successfully decrypted and saved to {output_path}")

# Tkinter Interface
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption")

        self.shared_key = perform_key_exchange()  # Get the shared key for both sides
        self.create_main_page()

    def create_main_page(self):
        """Create the main page with text/image selection."""
        self.clear_window()

        label = tk.Label(self.root, text="Do you want to encrypt a Text message or an Image?", font=("Arial", 14))
        label.pack(pady=20)

        text_button = tk.Button(self.root, text="Text", width=20, command=self.open_text_page)
        text_button.pack(pady=10)

        image_button = tk.Button(self.root, text="Image", width=20, command=self.open_image_page)
        image_button.pack(pady=10)

    def open_text_page(self):
        """Open the text encryption/decryption page."""
        self.clear_window()

        label = tk.Label(self.root, text="Text Encryption and Decryption", font=("Arial", 14))
        label.pack(pady=20)

        # Input for encryption
        encrypt_label = tk.Label(self.root, text="Enter message to encrypt:")
        encrypt_label.pack(pady=5)
        self.encrypt_entry = tk.Entry(self.root, width=50)
        self.encrypt_entry.pack(pady=5)

        encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_text)
        encrypt_button.pack(pady=10)

        # Output for encrypted message
        self.encrypted_text_box = tk.Text(self.root, height=5, width=50)
        self.encrypted_text_box.pack(pady=5)

        # Input for decryption
        decrypt_label = tk.Label(self.root, text="Enter encrypted message to decrypt:")
        decrypt_label.pack(pady=5)
        self.decrypt_entry = tk.Entry(self.root, width=50)
        self.decrypt_entry.pack(pady=5)

        decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_text)
        decrypt_button.pack(pady=10)

        # Output for decrypted message
        self.decrypted_text_box = tk.Text(self.root, height=5, width=50)
        self.decrypted_text_box.pack(pady=5)

        back_button = tk.Button(self.root, text="Back", width=20, command=self.create_main_page)
        back_button.pack(pady=20)

    def encrypt_text(self):
        """Encrypt the text input and display the encrypted output."""
        plaintext = self.encrypt_entry.get().encode()
        iv, ciphertext, tag = aes_encrypt(self.shared_key, plaintext)

        encrypted_message = f"Ciphertext: {binascii.hexlify(ciphertext).decode()}\nIV: {binascii.hexlify(iv).decode()}\nHMAC Tag: {binascii.hexlify(tag).decode()}"
        self.encrypted_text_box.delete(1.0, tk.END)
        self.encrypted_text_box.insert(tk.END, encrypted_message)

    def decrypt_text(self):
        """Decrypt the text input and display the decrypted output."""
        encrypted_text = self.decrypt_entry.get()
        try:
            parts = encrypted_text.split('\n')
            ciphertext = binascii.unhexlify(parts[0].split(": ")[1])
            iv = binascii.unhexlify(parts[1].split(": ")[1])
            tag = binascii.unhexlify(parts[2].split(": ")[1])
            
            decrypted_message = aes_decrypt(self.shared_key, iv, ciphertext, tag)
            self.decrypted_text_box.delete(1.0, tk.END)
            self.decrypted_text_box.insert(tk.END, decrypted_message.decode())
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt message: {str(e)}")

    def open_image_page(self):
        """Open the image encryption/decryption page."""
        self.clear_window()

        label = tk.Label(self.root, text="Image Encryption and Decryption", font=("Arial", 14))
        label.pack(pady=20)

        # Input for image encryption
        image_label = tk.Label(self.root, text="Select image to encrypt:")
        image_label.pack(pady=5)
        self.image_path_entry = tk.Entry(self.root, width=50)
        self.image_path_entry.pack(pady=5)
        browse_button = tk.Button(self.root, text="Browse", command=self.browse_image)
        browse_button.pack(pady=5)

        encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_image)
        encrypt_button.pack(pady=10)

        self.encrypted_image_box = tk.Text(self.root, height=5, width=50)
        self.encrypted_image_box.pack(pady=5)

        # Decrypt image
        decrypt_image_label = tk.Label(self.root, text="Select path to save decrypted image:")
        decrypt_image_label.pack(pady=5)
        self.decrypted_image_path_entry = tk.Entry(self.root, width=50)
        self.decrypted_image_path_entry.pack(pady=5)

        decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_image)
        decrypt_button.pack(pady=10)

    def encrypt_image(self):
        """Encrypt the image and display the encrypted byte value."""
        image_path = self.image_path_entry.get()
        iv, ciphertext, tag = encrypt_image(self.shared_key, image_path)

        encrypted_image = f"Ciphertext: {binascii.hexlify(ciphertext).decode()}\nIV: {binascii.hexlify(iv).decode()}\nHMAC Tag: {binascii.hexlify(tag).decode()}"
        self.encrypted_image_box.delete(1.0, tk.END)
        self.encrypted_image_box.insert(tk.END, encrypted_image)

    def decrypt_image(self):
        """Decrypt the image and save the output."""
        encrypted_image = self.encrypted_image_box.get(1.0, tk.END)
        parts = encrypted_image.split('\n')
        ciphertext = binascii.unhexlify(parts[0].split(": ")[1])
        iv = binascii.unhexlify(parts[1].split(": ")[1])
        tag = binascii.unhexlify(parts[2].split(": ")[1])

        output_path = self.decrypted_image_path_entry.get()
        decrypt_image(self.shared_key, iv, ciphertext, tag, output_path)

    def browse_image(self):
        """Open file dialog to select an image."""
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.image_path_entry.delete(0, tk.END)
            self.image_path_entry.insert(0, file_path)

    def clear_window(self):
        """Clear the current window."""
        for widget in self.root.winfo_children():
            widget.destroy()

# Main program
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
