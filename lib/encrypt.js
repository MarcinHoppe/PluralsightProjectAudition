const crypto = require('crypto');
function encrypt(plaintext, password) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 16);
    const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
    let ciphertext = cipher.update(plaintext, 'utf-8', 'hex');
    ciphertext += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return { salt, iv, ciphertext, tag };
}
module.exports = encrypt;