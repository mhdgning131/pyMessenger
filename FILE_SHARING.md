# File Sharing Feature Documentation

## Overview

pyMessenger now supports secure end-to-end encrypted file sharing between users. Files are automatically organized in user-specific folders with accept/reject functionality.

## Features

✨ **End-to-End Encryption**: Files are encrypted in chunks using AES-256 before transmission
📁 **Automatic Folder Management**: Received files are automatically saved to `~/.secure_messenger_client/files/received/`
✅ **Accept/Reject System**: Recipients can choose to accept or decline incoming files
📊 **Progress Tracking**: Real-time progress updates during file transfer
🔐 **Secure Storage**: Files are prefixed with sender's username to avoid conflicts

## File Storage Structure

```
~/.secure_messenger_client/
├── keys/                    # User encryption keys
├── files/
│   ├── received/           # Files received from others
│   │   ├── alice_document.pdf
│   │   ├── bob_image.jpg
│   │   └── ...
│   └── sent/               # Copy of files you've sent
│       └── ...
```

## Commands

### Sending Files

```bash
/sendfile <username> <filepath>
```

**Example:**
```bash
/sendfile alice ~/Documents/report.pdf
/sendfile bob /home/user/image.png
```

- The recipient will receive a notification and can choose to accept or reject
- Files are split into 64KB chunks for efficient transfer
- Progress is displayed during transmission

### Receiving Files

When someone sends you a file, you'll see a notification like:

```
═══════════════════════════════════════════════════════════
  📁 FILE TRANSFER REQUEST
═══════════════════════════════════════════════════════════
  alice wants to send you a file:

  Filename: report.pdf
  Size: 2.45 MB

  Type /acceptfile 1 to accept
  Type /rejectfile 1 to reject
═══════════════════════════════════════════════════════════
```

### Accepting Files

```bash
/acceptfile          # Show list of pending file offers
/acceptfile <number> # Accept specific file (e.g., /acceptfile 1)
```

**Example:**
```bash
> /acceptfile
Pending file offers:
  1. report.pdf (2.45 MB) from alice
     File ID: xYz123...

Usage: /acceptfile <number>

> /acceptfile 1
✓ Accepting file: report.pdf
  Waiting for transfer to begin...
  
  Receiving: 10.0% (10/100)
  Receiving: 50.0% (50/100)
  Receiving: 100.0% (100/100)

✓ File received successfully!
  From: alice
  Saved as: alice_report.pdf
  Location: /home/user/.secure_messenger_client/files/received/alice_report.pdf
  Size: 2.45 MB
```

### Rejecting Files

```bash
/rejectfile          # Show list of pending file offers
/rejectfile <number> # Reject specific file (e.g., /rejectfile 1)
```

## How It Works

### 1. File Offer Phase
- Sender initiates transfer with `/sendfile`
- Server relays the offer to recipient
- Recipient sees notification with file details

### 2. Accept/Reject Phase
- Recipient uses `/acceptfile` or `/rejectfile`
- Response is relayed back to sender through server

### 3. Transfer Phase (if accepted)
- File is split into 64KB chunks
- Each chunk is encrypted with AES-256
- AES key is encrypted with recipient's RSA public key
- Chunks are sent and reassembled on recipient's side
- Progress updates shown every 10 chunks

### 4. Storage Phase
- Completed file is saved to received folder
- Filename is prefixed with sender's username
- Duplicate filenames get numbered suffix (_1, _2, etc.)

## Security Features

🔐 **End-to-End Encryption**
- Files never stored on server
- Each chunk encrypted with unique AES key
- AES keys encrypted with RSA-2048

🛡️ **Privacy Protection**
- Files prefixed with sender username
- Automatic folder separation
- Secure file permissions on Unix systems

✅ **Integrity Protection**
- Each chunk includes authentication tag
- Tampering detected automatically

## Limitations

- Maximum recommended file size: **100 MB** (for optimal performance)
- Both users must be online for transfer
- Files stored locally (no cloud backup)
- Transfer interrupts if either user disconnects

## Troubleshooting

**File not found error:**
```bash
✗ File not found: ~/Documents/report.pdf
```
- Check the file path is correct
- Use absolute paths or correct relative paths
- Expand `~` to full home directory if needed

**User not online:**
```bash
⚠ User 'alice' is not online.
```
- Recipient must be connected to receive files
- Check with `/users` command

**Transfer interrupted:**
- If connection drops during transfer, retry from the beginning
- Partial transfers are not saved

## Examples

### Send a document to a colleague
```bash
/sendfile bob ~/Documents/proposal.docx
```

### Send an image
```bash
/sendfile alice /home/user/Pictures/photo.jpg
```

### Send a large file
```bash
/sendfile charlie ~/Videos/presentation.mp4
```

## Best Practices

1. ✅ **Check file size** before sending large files
2. ✅ **Verify recipient** is online with `/users`
3. ✅ **Use descriptive filenames** for clarity
4. ✅ **Clean up received folder** periodically
5. ✅ **Verify file integrity** after receiving important files

## Future Enhancements

- [ ] Resume interrupted transfers
- [ ] Compression for large files
- [ ] File preview/thumbnails
- [ ] Batch file transfers
- [ ] Transfer speed optimization
- [ ] File expiration/auto-cleanup

---

**Note**: File sharing uses the same end-to-end encryption as messages, ensuring complete privacy and security for your data.
