#!/usr/bin/env node

const lib = require('../lib/index.js');
var WebSocketServer = require('websocket').server;
var http = require('http');

if (!process.env.NODE_CONFIG_DIR){
    process.env.NODE_CONFIG_DIR = __dirname+"/../config/";
}
var config = require("config");

var logger = lib.Logger(config.get('winston'));
var app = new lib.App(logger);
var http_server = new lib.HttpServer(config.get('miniserver'), app);
var ws_server = new lib.WSServer(config.get('miniserver'), http_server);
