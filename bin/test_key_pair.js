#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');

if (!process.env.NODE_CONFIG_DIR){
    process.env.NODE_CONFIG_DIR = __dirname+"/../config/";
}

var iv = crypto.randomBytes(16);
var key = crypto.createHash('sha256').update(crypto.randomBytes(16).toString('hex')).digest();

var text=Buffer.from(key.toString('hex')+':'+iv.toString('hex'));

var pub = {
    key: fs.readFileSync(process.env.NODE_CONFIG_DIR + 'public.key'),
//    padding: crypto.constants.RSA_NO_PADDING,
    padding: crypto.constants.RSA_PKCS1_PADDING,
};
var priv = {
    key: fs.readFileSync(process.env.NODE_CONFIG_DIR + 'private.key'),
    padding: crypto.constants.RSA_PKCS1_PADDING,
};

console.log('input: '+text.toString());

var enc = crypto.publicEncrypt(pub, text);

console.log('output: '+crypto.privateDecrypt(priv, enc).toString());
