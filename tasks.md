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

Open the `lib/encrypt.js` file and call the built in `require` function passing `crypto` as its only argument. Assign the return value to `crypto` constant.

## Exporting the encrypt function

Declare an empty function `encrypt` taking two parameters: `plaintext` and `password`. Export the function by assigning it to `module.exports` at the end of the file.

## Generating salt and initialization vector

Generate a 16 byte random value by calling `crypto.randomBytes` function and passing `16` as its only argument. Assign the return value to `salt` constant. Generate a second 16 byte random value in the same way and assign it to `iv` constant.

## Deriving encryption key

Device encryption key from the password using the scrypt algorithm by calling the `crypto.scryptSync` function and passing `password`, `salt`, and `16` as arguments. Assign the return value to `key` constant.

## Creating the cipher object

Create the AES-GCM encryption object by calling `crypto.createCipheriv` function and passing `'aes-128-gcm'`, `key`, and `iv` as arguments. Assign the return value to `cipher` constant.

## Encrypting data

Declare a variable `ciphertext` to hold the hex encoded encrypted data. Input data in the `plaintext` variable is encoded using UTF-8. To encrypt the data call `cipher.update` function passing `plaintext`, `'utf-8'`, and `'hex'` as arguments and assign the return value to the `ciphertext` variable. To finalize encryption call `cipher.final` with a single argument `hex`. Append the return value to the `ciphertext` variable using addition assignment operator (`+=`).

## Obtaining authentication tag

AES-GCM is an authenticated encryption algorithm and the encryption process produces ciphertext and authentication tag. Retrieve the authentication tag by calling the `cipher.getAuthTag` function without any arguments and store the result in the `tag` constant.

## Returning the encryption data

To allow the data to be decrypted in the future return an object from the `encrypt` function. The object should contain `salt`, `iv`, `ciphertext`, and `tag` fields.
