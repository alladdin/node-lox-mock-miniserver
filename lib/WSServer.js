const crypto = require('crypto');
const fs = require('fs');
const events = require('events');
const util = require('util');
var WebSocketServer = require('websocket').server;

var WSServer = function(config, http_server) {
    var that = this;
    this.logger = http_server.logger;
    this.app = http_server.app;
    this.http_server = http_server;
    this.config = config;
    this.event_intervals = [];

    this.structure = JSON.parse(fs.readFileSync(process.env.NODE_CONFIG_DIR + this.config.structure_file));

    this.structure.msInfo.currentUser.name = this.config.username;

    this.public_key_file = fs.readFileSync(process.env.NODE_CONFIG_DIR + this.config.public_key);
    this.private_key = {
        'key': fs.readFileSync(process.env.NODE_CONFIG_DIR + this.config.private_key),
        'padding': crypto.constants.RSA_PKCS1_PADDING,
    };

    this.server = new WebSocketServer({
        httpServer: http_server.server,
        autoAcceptConnections: false
    });

    this.http_server.add_route('^/jdev/sys/getPublicKey', function(request, response){
        var data = JSON.stringify({ 'LL': { 'control': '/jdev/sys/getPublicKey', 'value': that.public_key_file.toString(), 'Code': '200'}});
        that.http_server.text_response(response, data);
    });

    this.server.on('request', function(request){
        new WSConnection(request, that);
    });

    this.server.on('close', function(connection, reason, description) {
        that.logger.info('WS Server closed');
    });

    this.app.prependListener('exit', function(code) {
        that.event_intervals.forEach(function(item){
            clearInterval(item);
        });
        that.server.shutDown();
    });

    this.config.value_events.forEach(function(evt){
        that.event_intervals.push(
            setInterval(function(){
                that.logger.debug("Send value event for "+evt.uuid);
                var binary = Buffer.alloc(24);
                that.write_uuid_to_buffer(binary, evt.uuid);
                binary.writeDoubleLE(evt.value, 16);
                that.emit('value_event', binary);
            }, evt.every_seconds * 1000)
        )
    });
};

util.inherits(WSServer, events.EventEmitter);

WSServer.prototype.write_uuid_to_buffer = function(buffer, uuid, offset = 0){
    var parts = uuid.split('-');
    var data1 = Buffer.from(parts[0], 'hex');
    var data2 = Buffer.from(parts[1], 'hex');
    var data3 = Buffer.from(parts[2], 'hex');

    buffer.writeUInt32LE(data1.readUInt32BE(0), 0);
    buffer.writeUInt16LE(data2.readUInt16BE(0), 4);
    buffer.writeUInt16LE(data3.readUInt16BE(0), 6);
    buffer.write(parts[3], 8, 8, 'hex');
};

var WSConnection = function(request, ws_server) {
    var that = this;
    this.logger = ws_server.logger;
    this.connection = request.accept('remotecontrol', request.origin);
    this.logger.info('Connection accepted from ' + this.connection.remoteAddress);
    this.key = Buffer.from(crypto.createHash('sha256').update(crypto.randomBytes(16).toString('hex')).digest().toString('hex'));
    this.hmac_hash;
    this.aes = {
        iv: undefined,
        key: undefined,
    };

    this._value_event_callback = function(data){
        that.send_events(data);
    };

    this._route = [
        {
            path: '^jdev/sys/getkey',
            handler: function(message) {
                that.send_text_message(message, that.key.toString('hex'));
            },
        },
        {
            path: '^authenticate/',
            handler: function(message) {
                var hmac = crypto.createHmac('sha1', that.key);
                that.hmac_hash = hmac.update(ws_server.config.username+':'+ws_server.config.password).digest('hex');
                if (message === 'authenticate/'+that.hmac_hash){
                    that.send_text_message(message, 1);
                }else{
                    that.send_text_message(message, 0, 304);
                }
            },
        },
        {
            path: '^jdev/sps/LoxAPPversion3',
            handler: function(message) {
                that.send_text_message(message, ws_server.structure.lastModified);
            },
        },
        {
            path: '^data/LoxAPP3.json',
            handler: function(message) {
                that.send_text_file(JSON.stringify(ws_server.structure));
            },
        },
        {
            path: '^jdev/sps/enablebinstatusupdate',
            handler: function(message) {
                that.send_text_message(message, 1);
                ws_server.on('value_event', that._value_event_callback);
            },
        },
        {
            path: '^jdev/sys/keyexchange/',
            handler: function(message) {
                var encrypted_session_key = Buffer.from(message.slice(21), 'base64');
                var session_key = crypto.privateDecrypt(ws_server.private_key, encrypted_session_key).toString().split(':', 2);
                that.aes.key = Buffer.from(session_key[0], 'hex');
                that.aes.iv = Buffer.from(session_key[1], 'hex');
                that.send_text_message(message, that._cipher(that.key.toString('hex'), 'base64'));
            },
        },
        {
            path: '^authenticateEnc/',
            handler: function(message) {
                var hmac = crypto.createHmac('sha1', that.key);
                that.hmac_hash = hmac.update(ws_server.config.username+':'+ws_server.config.password).digest('hex');
                var dec_message = that._decipher(message.slice(16));
                if (dec_message === that.hmac_hash+'/'+ws_server.config.username){
                    that.send_text_message(message, 1);
                }else{
                    that.send_text_message(message, 0, 304);
                }
            },
        },
    ];

    this.connection.on('message', function(message) {
        if (message.type === 'utf8') {
            that.logger.debug('Received Message: ' + message.utf8Data);
            if (!that._route.some(
                function(route) {
                    if (message.utf8Data.match(route.path)){
                        route.handler(message.utf8Data);
                        return true;
                    }
                    return false;
                }
            , that)) {
                that.logger.debug("No response for that message!");
            }
        }
        else if (message.type === 'binary') {
            that.logger.error('Received Binary Message of ' + message.binaryData.length + ' bytes');
        }
    });

    this.connection.on('close', function(reasonCode, description) {
        ws_server.removeListener('value_event', that._value_event_callback);
        that.logger.info('Peer ' + that.connection.remoteAddress + ' disconnected.');
    });
}

WSConnection.prototype.send_text_message = function(control, value, code = 200) {
    var header = Buffer.from([0x03, 0, 0, 0, 0, 0, 0, 0]);
    var response_data = Buffer.from(
        JSON.stringify({ 'LL': { 'control': ''+control, 'value': ''+value, 'Code': ''+code}})
    );
    header.writeUInt32LE(response_data.length, 4);
    this.connection.sendBytes(header);
    this.connection.sendUTF(response_data);
};

WSConnection.prototype.send_text_file = function(data) {
    var header = Buffer.from([0x03, 0x01, 0, 0, 0, 0, 0, 0]);
    header.writeUInt32LE(data.length, 4);
    this.connection.sendBytes(header);
    this.connection.sendUTF(data);
};

WSConnection.prototype.send_events = function(data) {
    var header = Buffer.from([0x03, 0x02, 0, 0, 0, 0, 0, 0]);
    header.writeUInt32LE(data.length, 4);
    this.connection.sendBytes(header);
    this.connection.sendBytes(data);
};

WSConnection.prototype._decipher = function(enc_data) {
    var decipher = crypto.createDecipheriv('aes-256-cbc', this.aes.key, this.aes.iv);
    var data = decipher.update(enc_data,'base64','utf-8');
    data += decipher.final('utf-8');
    return data.replace(/\x00+$/,"");
};

WSConnection.prototype._cipher = function(data, out_enc) {
    var cipher = crypto.createCipheriv('aes-256-cbc', this.aes.key, this.aes.iv);
    var enc_data = cipher.update(data + "\0",'utf-8', out_enc);
    enc_data += cipher.final(out_enc);
    return enc_data;
};

module.exports = WSServer;