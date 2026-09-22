# Cryptix Requirements

R1 Encryption turns readable content into unreadable ciphertext with AES. After SUCCESSFUL, VERIFIED encryption the original plaintext must not remain in the normal folder.
R2 Decryption with the correct key restores the original file, byte for byte.
R3 AES encrypts the file contents. RSA protects (encrypts) the AES key. SHA-256 is a fingerprint used only for integrity, not encryption.
R4 SHA-256 converts content (including plain text) into a fixed-length hash. A tiny change gives a completely different hash.
R5 Before storage: File -> SHA-256 -> original hash. Later: File -> SHA-256 -> new hash. Equal = unchanged (SAFE). Different = changed/tampered (TAMPERED).
R6 Workflow: SHA-256 fingerprint -> AES encrypt -> RSA protects key -> stored as Encrypted file + Protected AES key + Hash. Decrypt: RSA recovers key -> AES decrypt -> SHA-256 verify.
R7 A folder is handled by encrypting each file separately; the folder structure is restored on decrypt; originals no longer remain accessible in the normal folder.
