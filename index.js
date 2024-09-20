const crypto = require('crypto');

const algorithm = 'aes-256-cbc';

// Function to encrypt text
function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Return IV and encrypted text
    return iv.toString('hex') + ':' + encrypted;
}

// Function to decrypt text
function decrypt(encryptedText, key) {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedTextBuffer = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedTextBuffer, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Example usage:
const key = crypto.randomBytes(32); // Generate a random 256-bit key || Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", 'hex');
console.log(`key: ${key.toString('hex')}`);
const originalText = "Hello, World!";
const encryptedText = encrypt(originalText, key);
const decryptedText = decrypt(encryptedText, key);

console.log("Original Text:", originalText);
console.log("Encrypted Text:", encryptedText);
console.log("Decrypted Text:", decryptedText);