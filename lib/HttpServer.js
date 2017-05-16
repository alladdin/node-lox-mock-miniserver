var http = require('http');

var HttpServer = function(config, app) {
    var that = this;
    this.logger = app.logger;
    this.app = app;
    this.port = config.port;

    this.server = http.createServer(
        function(request, response) {that.handle_request(request, response)});

    this.server.listen(this.port, function() {
        that.logger.info('HTTP Server is listening on port ' + that.port);
    });

    this.server.on('close', function() {
        that.logger.info('HTTP Server closed');
    });

    this.app.on('prepare_exit', function(code) {
        that.server.close();
    });

    this._route = [
        {
            path: '^/admin/exit',
            handler: function(request, response) {
                that.logger.info("request for exit");
                that.text_response(response, 'Try to exit', 200);
                that.app.exit(0, 'exit by request');
            },
        },
    ];
};

HttpServer.prototype.handle_request = function(request, response) {
    this.logger.debug('Received HTTP request for ' + request.url);
    if (!this._route.some(
        function(route) {
            if (request.url.match(route.path)){
                route.handler(request, response);
                return true;
            }
            return false;
        }
    , this)) {
        this.text_response(response, 'Not found!', 404);
    }
    response.end();
};

HttpServer.prototype.add_route = function(path, handler) {
    this._route.push({ "path": path, "handler": handler });
};

HttpServer.prototype.text_response = function(response, message, code) {
    code = typeof code !== 'undefined' ? code : 200;
    this.send_response(response, message, code, 'text/plain');
};

HttpServer.prototype.xml_response = function(response, message, code) {
    code = typeof code !== 'undefined' ? code : 200;
    this.send_response(response, message, code, 'text/xml');
};

HttpServer.prototype.json_response = function(response, message, code) {
    code = typeof code !== 'undefined' ? code : 200;
    this.send_response(response, message, code, 'application/json');
};

HttpServer.prototype.send_response = function(response, message, code, type) {
    code = typeof code !== 'undefined' ? code : 200;
    type = typeof type !== 'undefined' ? type : 'text/plain';
    var buf = Buffer.from(message);
    response.writeHead(code,
        {
            'Content-Type': type,
            'Content-length': buf.length,
            'Connection': 'close',
        }
    );
    response.end(buf);
};

module.exports = HttpServer;
