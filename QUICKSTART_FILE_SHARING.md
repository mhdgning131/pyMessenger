# Quick Start: File Sharing

## 🚀 Getting Started with File Sharing

### Prerequisites
✅ Server is running (`python3 server.py`)
✅ Both users are logged in
✅ You know the recipient's username

---

## 📤 Sending a File

### Step 1: Check who's online
```bash
> /users

Online users:
  1. alice
  2. bob
  3. charlie
```

### Step 2: Send the file
```bash
> /sendfile alice ~/Documents/report.pdf

→ Preparing to send file:
  File: report.pdf
  Size: 2.45 MB
  To: alice

Waiting for alice to accept...
```

### Step 3: Wait for acceptance
If alice accepts:
```bash
✓ alice accepted your file!
→ Starting file transfer...

→ Sending file in 40 chunks...
  Progress: 25.0% (10/40)
  Progress: 50.0% (20/40)
  Progress: 75.0% (30/40)
  Progress: 100.0% (40/40)

✓ File sent successfully!
```

If alice rejects:
```bash
✗ alice rejected your file.
```

---

## 📥 Receiving a File

### Step 1: You'll get a notification
```
═══════════════════════════════════════════════════════════
  📁 FILE TRANSFER REQUEST
═══════════════════════════════════════════════════════════
  bob wants to send you a file:

  Filename: presentation.pptx
  Size: 5.12 MB

  Type /acceptfile 1 to accept
  Type /rejectfile 1 to reject
═══════════════════════════════════════════════════════════
```

### Step 2: Accept or Reject

**To Accept:**
```bash
> /acceptfile 1

✓ Accepting file: presentation.pptx
  Waiting for transfer to begin...

  Receiving: 10.0% (8/80)
  Receiving: 50.0% (40/80)
  Receiving: 100.0% (80/80)

✓ File received successfully!
  From: bob
  Saved as: bob_presentation.pptx
  Location: /home/user/.secure_messenger_client/files/received/bob_presentation.pptx
  Size: 5.12 MB
```

**To Reject:**
```bash
> /rejectfile 1

✗ Rejected file: presentation.pptx
```

---

## 📂 Finding Your Files

### Received Files
```bash
cd ~/.secure_messenger_client/files/received/
ls -lh
```

You'll see files like:
```
alice_document.pdf
bob_presentation.pptx
charlie_image.jpg
```

Each file is prefixed with the sender's username!

### Sent Files (backup copies)
```bash
cd ~/.secure_messenger_client/files/sent/
```

---

## 💡 Pro Tips

### 1. Multiple Pending Files
If you have multiple file offers:

```bash
> /acceptfile

Pending file offers:
  1. report.pdf (2.45 MB) from alice
  2. image.png (1.23 MB) from bob
  3. video.mp4 (45.67 MB) from charlie

Usage: /acceptfile <number>

> /acceptfile 2    # Accept bob's file
```

### 2. Check File Size First
Large files take time! Check the size before accepting:
- **< 5 MB**: ⚡ Fast transfer
- **5-20 MB**: 🚀 Moderate transfer
- **20-50 MB**: 🐌 Slower transfer
- **> 50 MB**: ⏳ May take several minutes

### 3. Send from Anywhere
Use absolute or relative paths:

```bash
# Absolute path
> /sendfile alice /home/user/Documents/file.pdf

# Relative path (from current directory)
> /sendfile bob ./image.jpg

# Home directory shorthand
> /sendfile charlie ~/Downloads/document.docx
```

### 4. File Types
You can send ANY file type:
- Documents (PDF, DOCX, TXT, etc.)
- Images (JPG, PNG, GIF, etc.)
- Videos (MP4, AVI, MKV, etc.)
- Archives (ZIP, TAR, etc.)
- Code (PY, JS, C, etc.)

All are encrypted the same way! 🔐

---

## ⚠️ Troubleshooting

### "File not found"
```bash
✗ File not found: ~/Documents/report.pdf
```

**Solution:** Check the file path:
```bash
# List files to verify
ls ~/Documents/

# Try with full path
> /sendfile alice /home/user/Documents/report.pdf
```

### "User not online"
```bash
⚠ User 'alice' is not online.
```

**Solution:** Check who's online first:
```bash
> /users
```

### Transfer Interrupted
If connection drops during transfer:
1. File is NOT saved (incomplete)
2. Resend from the beginning
3. Make sure both users stay connected

### "No pending file offers"
```bash
⚠ No pending file offers.
```

**Solution:** Wait for someone to send you a file first!

---

## 🔐 Security Notes

✅ **Files are encrypted end-to-end**
- Server cannot read your files
- Only sender and recipient can decrypt

✅ **Each chunk uses unique encryption**
- Perfect forward secrecy
- Tampering detected automatically

✅ **Files stored locally only**
- Not uploaded to any cloud
- Complete control over your data

---

## 📊 Example Session

**Alice sends a file to Bob:**

```
[Alice's terminal]
> /sendfile bob ~/report.pdf

→ Preparing to send file:
  File: report.pdf
  Size: 2.45 MB
  To: bob

Waiting for bob to accept...
```

```
[Bob's terminal]
═══════════════════════════════════════════════════════════
  📁 FILE TRANSFER REQUEST
═══════════════════════════════════════════════════════════
  alice wants to send you a file:

  Filename: report.pdf
  Size: 2.45 MB

  Type /acceptfile 1 to accept
  Type /rejectfile 1 to reject
═══════════════════════════════════════════════════════════

> /acceptfile 1
✓ Accepting file: report.pdf
  Waiting for transfer to begin...
```

```
[Alice's terminal]
✓ bob accepted your file!
→ Starting file transfer...

→ Sending file in 40 chunks...
  Progress: 50.0% (20/40)
  Progress: 100.0% (40/40)

✓ File sent successfully!
```

```
[Bob's terminal]
  Receiving: 50.0% (20/40)
  Receiving: 100.0% (40/40)

✓ File received successfully!
  From: alice
  Saved as: alice_report.pdf
  Location: /home/bob/.secure_messenger_client/files/received/alice_report.pdf
  Size: 2.45 MB
```

**Done! 🎉**

---

## 📚 Learn More

- [FILE_SHARING.md](FILE_SHARING.md) - Complete documentation
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) - Technical details
- [README.md](README.md) - Main project documentation

---

**Happy file sharing! 🚀**
