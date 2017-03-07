#!/usr/bin/env node

var fs = require('fs');
var keypair = require('keypair');

if (!process.env.NODE_CONFIG_DIR){
    process.env.NODE_CONFIG_DIR = __dirname+"/../config/";
}

console.log('Generating private/public keys');
var pair = keypair();

fs.writeFileSync(process.env.NODE_CONFIG_DIR + 'public.key',pair.public);
fs.writeFileSync(process.env.NODE_CONFIG_DIR + 'private.key',pair.private);
