const assert = require('chai').assert;
const fs = require('fs');
const path = require('path');
const process = require('process');
const esprima = require('esprima');

const encrypt = require('../lib/encrypt');
const decrypt = require('./decrypt');

describe('Encrypt sensitive data', () => {
    const source = fs.readFileSync(path.join(process.cwd(), 'lib/encrypt.js'), 'utf8');

    describe('Importing the crypto module', () => {
        const ast = esprima.parseModule(source);

        it('Should declare crypto constant', () => {
            assert(ast.body.length >= 1, 'Have you declared crypto constant?');

            assert(ast.body[0].type === 'VariableDeclaration', 'Have you declared crypto constant?');
            assert(ast.body[0].kind === 'const', 'Have you declared crypto constant?');
            assert(ast.body[0].declarations[0].id.name === 'crypto', 'Have you declared crypto constant?');
        });

        it('Should require crypto module', () => {
            assert(ast.body[0].declarations[0].init.type === 'CallExpression', 'Have you called require with argument \'crypto\'?');
            assert(ast.body[0].declarations[0].init.callee.name === 'require', 'Have you called require with argument \'crypto\'?');
            assert(ast.body[0].declarations[0].init.arguments.length === 1, 'Have you called require with argument \'crypto\'?');
            assert(ast.body[0].declarations[0].init.arguments[0].value === 'crypto', 'Have you called require with argument \'crypto\'?');
        });
    });

    describe('Exporting the encrypt function', () => {
        it('Should export the encrypt function', () => {
            assert.typeOf(encrypt, 'function', 'Have you exported a function?');
            assert(encrypt.name === 'encrypt', 'Have you declared a function named encrypt?');
        });

        it('Should export function with two parameters', () => {
            assert(encrypt.length === 2, 'Does the encrypt function have two parameters?');
        });
    });

    describe('Generating salt and initialization vector', () => {
        let saltNode, ivNode;
        esprima.parseModule(source, {}, (node) => {
            if (node.type === 'VariableDeclarator') {
                switch (node.id.name) {
                    case 'salt': saltNode = node; break;
                    case 'iv': ivNode = node; break;
                }
            }
        });

        it('Should declare salt constant', () => {
            assert(saltNode, 'Have you declared salt constant?');
        });

        it('Should call crypto.randomBytes to generate salt', () => {
            assert(saltNode.init.type === 'CallExpression', 'Have you assigned return value of crypto.randomBytes to salt?');
            assert(saltNode.init.callee.type === 'MemberExpression', 'Have you called crypto.randomBytes?');
            assert(saltNode.init.callee.object.name === 'crypto', 'Have you called crypto.randomBytes?');
            assert(saltNode.init.callee.property.name === 'randomBytes', 'Have you called crypto.randomBytes?');
            assert(saltNode.init.arguments.length === 1, 'Have you called crypto.randomBytes with a parameter?');
            assert(saltNode.init.arguments[0].value === 16, 'Have you passed 16 as first argument to crypto.randomBytes?');
        });

        it('Should declare iv constant', () => {
            assert(ivNode, 'Have you declared iv constant?');
        });

        it('Should call crypto.randomBytes to generate initialization vector', () => {
            assert(ivNode.init.type === 'CallExpression', 'Have you assigned return value of crypto.randomBytes to iv?');
            assert(ivNode.init.callee.type === 'MemberExpression', 'Have you called crypto.randomBytes?');
            assert(ivNode.init.callee.object.name === 'crypto', 'Have you called crypto.randomBytes?');
            assert(ivNode.init.callee.property.name === 'randomBytes', 'Have you called crypto.randomBytes?');
            assert(ivNode.init.arguments.length === 1, 'Have you called crypto.randomBytes with a parameter?');
            assert(ivNode.init.arguments[0].value === 16, 'Have you passed 16 as first argument to crypto.randomBytes?');
        });
    });

    describe('Deriving encryption key', () => {
        let keyNode;
        esprima.parseModule(source, {}, (node) => {
            if (node.type === 'VariableDeclarator' && node.id.name === 'key') {
                keyNode = node;
            }
        });

        it('Should declare key constant', () => {
            assert(keyNode, 'Have you declared key constant?');
        });

        it('Should call crypto.scryptSync to derive encryption key', () => {
            assert(keyNode.init.type === 'CallExpression', 'Have you assigned return value of crypto.scryptSync to key?');
            assert(keyNode.init.callee.type === 'MemberExpression', 'Have you called crypto.scryptSync?');
            assert(keyNode.init.callee.object.name === 'crypto', 'Have you called crypto.scryptSync?');
            assert(keyNode.init.callee.property.name === 'scryptSync', 'Have you called crypto.scryptSync?');
            assert(keyNode.init.arguments.length === 3, 'Have you called crypto.scryptSync with all the parameters?');
            assert(keyNode.init.arguments[0].name === 'password', 'Have you passed password as first argument to crypto.scryptSync?');
            assert(keyNode.init.arguments[1].name === 'salt', 'Have you passed salt as second argument to crypto.scryptSync?');
            assert(keyNode.init.arguments[2].value === 16, 'Have you passed 16 as last argument to crypto.scryptSync?');
        });
    });

    describe('Creating the cipher object', () => {
        let cipherNode;
        esprima.parseModule(source, {}, (node) => {
            if (node.type === 'VariableDeclarator' && node.id.name === 'cipher') {
                cipherNode = node;
            }
        });

        it('Should declare cipher constant', () => {
            assert(cipherNode, 'Have you declared cipher constant?');
        });

        it('Should call crypto.createCipheriv to create cipher object', () => {
            assert(cipherNode.init.type === 'CallExpression', 'Have you assigned return value of crypto.createCipheriv to key?');
            assert(cipherNode.init.callee.type === 'MemberExpression', 'Have you called crypto.createCipheriv?');
            assert(cipherNode.init.callee.object.name === 'crypto', 'Have you called crypto.createCipheriv?');
            assert(cipherNode.init.callee.property.name === 'createCipheriv', 'Have you called crypto.createCipheriv?');
            assert(cipherNode.init.arguments.length === 3, 'Have you called crypto.createCipheriv with all the parameters?');
            assert(cipherNode.init.arguments[0].value === 'aes-128-gcm', 'Have you passed \'aes-128-gcm\' as first argument to crypto.createCipheriv?');
            assert(cipherNode.init.arguments[1].name === 'key', 'Have you passed key as second argument to crypto.createCipheriv?');
            assert(cipherNode.init.arguments[2].name === 'iv', 'Have you passed iv as last argument to crypto.createCipheriv?');
        });
    });

    describe('Encrypting data', () => {
        let ciphertextNode, appendNode;
        esprima.parseModule(source, {}, (node) => {
            if (node.type === 'VariableDeclarator' && node.id.name === 'ciphertext') {
                ciphertextNode = node;
            }
            if (node.type === 'AssignmentExpression' && node.operator === '+=') {
                appendNode = node;
            }
        });

        it('Should declare ciphertext variable', () => {
            assert(ciphertextNode, 'Have you declared ciphertext variable?');
        });

        it('Should call cipher.update to encrypt the data', () => {
            assert(ciphertextNode.init.type === 'CallExpression', 'Have you assigned return value of cipher.update to ciphertext?');
            assert(ciphertextNode.init.callee.type === 'MemberExpression', 'Have you called cipher.update?');
            assert(ciphertextNode.init.callee.object.name === 'cipher', 'Have you called cipher.update?');
            assert(ciphertextNode.init.callee.property.name === 'update', 'Have you called cipher.update?');
            assert(ciphertextNode.init.arguments.length === 3, 'Have you called cipher.update with all the parameters?');
            assert(ciphertextNode.init.arguments[0].name === 'plaintext', 'Have you passed plaintext as first argument to cipher.update?');
            assert(ciphertextNode.init.arguments[1].value === 'utf-8', 'Have you passed \'utf-8\' as second argument to cipher.update?');
            assert(ciphertextNode.init.arguments[2].value === 'hex', 'Have you passed \'hex\' as last argument to cipher.update?');
        });

        it('Should append results of cipher.final to ciphertext', () => {
            assert(appendNode, 'Have you appended the return value of cipher.final to ciphertext variable?');
            assert(appendNode.left.name === 'ciphertext', 'Have you appended the return value of cipher.final to ciphertext variable?');
            assert(appendNode.right.callee.type === 'MemberExpression', 'Have you called cipher.final?');
            assert(appendNode.right.callee.object.name === 'cipher', 'Have you called cipher.final?');
            assert(appendNode.right.callee.property.name === 'final', 'Have you called cipher.final?');
            assert(appendNode.right.arguments.length === 1, 'Have you called cipher.final with parameter?');
            assert(appendNode.right.arguments[0].value === 'hex', 'Have you passed \'hex\' as argument to cipher.final?');
        });
    });

    describe('Obtaining authentication tag', () => {
        let tagNode;
        esprima.parseModule(source, {}, (node) => {
            if (node.type === 'VariableDeclarator' && node.id.name === 'tag') {
                tagNode = node;
            }
        });

        it('Should declare tag constant', () => {
            assert(tagNode, 'Have you declared tag constant?');
        });

        it('Should call cipher.getAuthTag to retrieve authentication tag', () => {
            assert(tagNode.init.type === 'CallExpression', 'Have you assigned return value of cipher.getAuthTag to key?');
            assert(tagNode.init.callee.type === 'MemberExpression', 'Have you called cipher.getAuthTag?');
            assert(tagNode.init.callee.object.name === 'cipher', 'Have you called cipher.getAuthTag?');
            assert(tagNode.init.callee.property.name === 'getAuthTag', 'Have you called cipher.getAuthTag?');
        });
    });

    describe('Returning the encryption data', () => {
        it('Should return encryption object', () => {
            const encryptionData = encrypt('secretdata', 's3cr3t');

            assert(encryptionData, 'Have you returned object data from encrypt function?');
            assert.typeOf(encryptionData, 'object', 'Have you returned object data from encrypt function?');
            assert(encryptionData.salt, 'Have you included salt in returned object?');
            assert(encryptionData.iv, 'Have you included iv in returned object?');
            assert(encryptionData.ciphertext, 'Have you included ciphertext in returned object?');
            assert(encryptionData.tag, 'Have you included tag in returned object?');
        });

        it('Should decrypt data correctly', () => {
            const crypto = require('crypto');

            const plaintext = 'secretdata';
            const password = 's3cr3t';

            const { salt, iv, ciphertext, tag } = encrypt(plaintext, password);

            const decryptedPlaintext = decrypt(password, ciphertext, salt, iv, tag);

            assert(decryptedPlaintext === plaintext, 'Have you properly encrypted data?');
        });
    });
});