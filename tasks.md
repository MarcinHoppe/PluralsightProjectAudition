# Setup

## Installation

Run the following command from the root folder to install all the necessary dependencies:

```bash
npm install
```

## Verify Setup

The best way to verify if everything is set up correctly is to run the tests. You can run the tests using the following command:

```bash
npm test
```

All tests should be failing now. This is expected.

# Tasks

## Importing the crypto module

Open the `lib/encrypt.js` file. Declare a constant `crypto` and initialize it with a call to the built in `require` function. Pass the string `'crypto'` as its only argument.

## Exporting the encrypt function

Declare an empty function `encrypt` taking two parameters: `plaintext` and `password`. Export the function by assigning it to `module.exports` at the end of the file.

## Generating salt and initialization vector

Declare two constants: `salt` and `iv`. Initialize each of them with a call to the `crypto.randomBytes` function. Pass the number `16` as its only argument.

## Deriving encryption key

Derive encryption key from the password using the `scrypt` algorithm. To do this, declare a constant `key` and initialize it with a call to the `crypto.scryptSync` function. Pass variables `password`, `salt`, and the number `16` as arguments.

## Creating the cipher object

We will use a cipher object implementing the AES-GCM algorithm to encrypt the data. Declare a constant `cipher` and initialize it with a call to the `crypto.createCipheriv` function. Pass the string `'aes-128-gcm'`, followed by variables `key` and `iv` as arguments.

## Encrypting data

Declare a variable `ciphertext` to hold the hex encoded encrypted data. Input data in the `plaintext` variable is encoded using UTF-8. Initialize the `ciphertext` variable with a call to the `cipher.update` function. Pass variable `plaintext`, followed by strings `'utf-8'` and `'hex'` as arguments. To finalize encryption, append the result of call to `cipher.final` with a single argument `'hex'` to the `ciphertext` variable using addition assignment operator (`+=`).

## Obtaining authentication tag

AES-GCM is an authenticated encryption algorithm and the encryption process produces ciphertext and authentication tag. Declare a constant `tag` and initialize it with a calling to the `cipher.getAuthTag` function without any arguments.

## Returning the encryption data

To allow the data to be decrypted in the future return an object from the `encrypt` function. The object should contain `salt`, `iv`, `ciphertext`, and `tag` fields.
