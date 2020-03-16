const crypto = require('crypto');
function decrypt(password, ciphertext, salt, iv, tag) {
    const key = crypto.scryptSync(password, salt, 16);
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
    decipher.setAuthTag(tag);
    let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
}
module.exports = decrypt;