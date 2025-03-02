# Secure Data Hiding in Image Using Steganography 🛡️

**A Python-based tool to securely hide and encrypt messages inside images using Least Significant Bit (LSB) steganography with Fernet encryption.**

---

## 🚀 Features
- **Data Encryption:** Encrypt messages using AES-like Fernet encryption.
- **Image Steganography:** Hide encrypted data inside images using LSB.
- **Integrity Verification:** Hash-based verification to check data integrity.
- **CLI Tool:** Command-line interface with flexible encoding/decoding options.

---

## 🛠️ Installation
1. Clone the repository:
```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
cd YOUR-REPOSITORY
```

2. Create a virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

---

## 🧩 Usage

### 🔑 Generate an Encryption Key
```bash
python steganography.py generate_key --save-key key.key
```
Or print the key directly:
```bash
python steganography.py generate_key
```

### 🖼️ Encode a Message into an Image
```bash
python steganography.py encode \
    --image input.jpg \
    --output encoded_image.jpg \
    --message "Your secret message" \
    --key key.key \
    --bits 2
```

### 🔓 Decode the Message from an Image
```bash
python steganography.py decode \
    --image encoded_image.jpg \
    --key key.key \
    --bits 2
```

---

## 📂 Example
```bash
python steganography.py encode --image bugatti.jpg --output encoded_bugatti.jpg --message "Hidden message!" --key key.key --bits 1
```
Output:
```
Message successfully hidden in encoded_bugatti.jpg
```

```bash
python steganography.py decode --image encoded_bugatti.jpg --key key.key --bits 1
```
Output:
```
Decoded message: Hidden message!
```

---

## 📜 License
This project is licensed under the **MIT License** — feel free to use and improve it!

---

## 📈 Future Improvements
- **Support for Audio/Video Steganography**
- **GUI Version with Drag-and-Drop Features**
- **Integration with Blockchain for Tamper-proof Storage**
- **Machine Learning for Steganalysis Detection**

---

## 👤 Author
- K HEMA HARIKESH — [GitHub](https://github.com/KH-HARIKESH)
