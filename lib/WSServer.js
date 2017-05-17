const crypto = require('crypto');
const constants = require('constants');
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
    this.key = new Buffer(crypto.createHash('sha256').update(crypto.randomBytes(16).toString('hex')).digest().toString('hex'));

    this.structure = JSON.parse(fs.readFileSync(process.env.NODE_CONFIG_DIR + this.config.structure_file));

    this.structure.msInfo.currentUser.name = this.config.username;

    this.public_key_file = fs.readFileSync(process.env.NODE_CONFIG_DIR + this.config.public_key);
    this.private_key = {
        'key': fs.readFileSync(process.env.NODE_CONFIG_DIR + this.config.private_key),
        'padding': constants.RSA_PKCS1_PADDING,
    };

    this.server = new WebSocketServer({
        httpServer: http_server.server,
        autoAcceptConnections: false
    });

    this.http_server.add_route('^/jdev/sys/getPublicKey', function(request, response){
        var data = JSON.stringify({ 'LL': { 'control': '/jdev/sys/getPublicKey', 'value': that.public_key_file.toString(), 'Code': '200'}});
        that.http_server.json_response(response, data);
    });

    this.http_server.add_route('^/data/LoxAPP3.json', function(request, response){
        if (!request.headers.authorization){
            response.setHeader('WWW-Authenticate', 'Basic realm="User/Password"');
            return that.http_server.text_response(response, 'Unauthorized', 401);
        }

        var auth_str = 'Basic '+ new Buffer(that.config.username+':'+that.config.password).toString('base64');
        if (request.headers.authorization !== auth_str) {
            return that.http_server.text_response(response, 'Authorization failed!', 403);
        }
        that.http_server.json_response(response, JSON.stringify(that.structure));
    });

    this.add_routes_for_config();

    this.server.on('request', function(request){
        new WSConnection(request, that);
    });

    this.server.on('close', function(connection, reason, description) {
        that.logger.info('WS Server closed');
    });

    this.app.on('prepare_exit', function(code) {
        that.event_intervals.forEach(function(item){
            clearInterval(item);
        });
        that.server.shutDown();
    });

    this.config.value_events.forEach(function(evt){
        that.event_intervals.push(
            setInterval(function(){
                that.logger.debug("Send value event for "+evt.uuid);
                var binary = new Buffer(24);
                that.write_uuid_to_buffer(binary, evt.uuid);
                binary.writeDoubleLE(evt.value, 16);
                that.emit('value_event', binary);
            }, evt.every_seconds * 1000)
        )
    });
};

util.inherits(WSServer, events.EventEmitter);

WSServer.prototype.write_uuid_to_buffer = function(buffer, uuid, offset){
    offset = typeof offset !== 'undefined' ? offset : 0;
    var parts = uuid.split('-');
    var data1 = new Buffer(parts[0], 'hex');
    var data2 = new Buffer(parts[1], 'hex');
    var data3 = new Buffer(parts[2], 'hex');

    buffer.writeUInt32LE(data1.readUInt32BE(0), 0);
    buffer.writeUInt16LE(data2.readUInt16BE(0), 4);
    buffer.writeUInt16LE(data3.readUInt16BE(0), 6);
    buffer.write(parts[3], 8, 8, 'hex');
};

WSServer.prototype.add_routes_for_config = function() {
    var that = this;
    this.http_server.add_route('^/dev/sys/check', function(request, response){
        that.http_server.xml_response(response, '<LL control="dev/sys/check" value="0:No connection" Code="200"/>');
    });
    this.http_server.add_route('^/dev/cfg/api', function(request, response){
        that.http_server.xml_response(response, "<LL control=\"dev/cfg/api\" value=\"{'snr': '70:4A:95:21:33:41', 'version':'8.1.11.11'}\" Code=\"200\"/>");
    });
    this.http_server.add_route('^/dev/sys/getkey', function(request, response){
        that.http_server.xml_response(response, "<LL control=\"dev/sys/getkey\" value=\""+that.key.toString('hex')+"\" Code=\"200\"/>");
    });
}

var WSConnection = function(request, ws_server) {
    var that = this;
    this.logger = ws_server.logger;
    this.connection = request.accept('remotecontrol', request.origin);
    this.logger.info('Connection accepted from ' + this.connection.remoteAddress);
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
                that.send_text_message(message, ws_server.key.toString('hex'));
            },
        },
        {
            path: '^authenticate/',
            handler: function(message) {
                var hmac = crypto.createHmac('sha1', ws_server.key);
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
                var encrypted_session_key = new Buffer(message.slice(21), 'base64');
                var session_key = crypto.privateDecrypt(ws_server.private_key, encrypted_session_key).toString().split(':', 2);
                that.aes.key = new Buffer(session_key[0], 'hex');
                that.aes.iv = new Buffer(session_key[1], 'hex');
                that.send_text_message(message, that._cipher(ws_server.key.toString('hex'), 'base64'));
            },
        },
        {
            path: '^authenticateEnc/',
            handler: function(message) {
                var hmac = crypto.createHmac('sha1', ws_server.key);
                that.hmac_hash = hmac.update(ws_server.config.username+':'+ws_server.config.password).digest('hex');
                var dec_message = that._decipher(message.slice(16));
                if (dec_message === that.hmac_hash+'/'+ws_server.config.username){
                    that.send_text_message(message, 1);
                }else{
                    that.send_text_message(message, 0, 304);
                }
            },
        },
        {
            path: '^jdev/sys/enc/',
            handler: function(message) {
                var dec_message = that._decipher(decodeURIComponent(message.slice(13)));
                dec_message = dec_message.replace(/^salt\/[^\/]*\//, "");
                dec_message = dec_message.replace(/^nextSalt\/[^\/]*\/[^\/]*\//, "");
                that.logger.debug('Decrypted Message: ' + dec_message);
                that.route_path(dec_message);
            }
        },
    ];

    this.connection.on('message', function(message) {
        if (message.type === 'utf8') {
            that.logger.debug('Received Message: ' + message.utf8Data);
            that.route_path(message.utf8Data);
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

WSConnection.prototype.route_path = function(message) {
    if (!this._route.some(
        function(route) {
            if (message.match(route.path)){
                route.handler(message);
                return true;
            }
            return false;
        }
    , this)) {
        this.logger.debug("No response for that message!");
    }
};

WSConnection.prototype.send_text_message = function(control, value, code) {
    code = typeof code !== 'undefined' ? code : 200;
    var header = new Buffer([0x03, 0, 0, 0, 0, 0, 0, 0]);
    var response_data = new Buffer(
        JSON.stringify({ 'LL': { 'control': ''+control, 'value': ''+value, 'Code': ''+code}})
    );
    header.writeUInt32LE(response_data.length, 4);
    this.connection.sendBytes(header);
    this.connection.sendUTF(response_data);
};

WSConnection.prototype.send_text_file = function(data) {
    var header = new Buffer([0x03, 0x01, 0, 0, 0, 0, 0, 0]);
    header.writeUInt32LE(data.length, 4);
    this.connection.sendBytes(header);
    this.connection.sendUTF(data);
};

WSConnection.prototype.send_events = function(data) {
    var header = new Buffer([0x03, 0x02, 0, 0, 0, 0, 0, 0]);
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
