const util = require('util');
const events = require('events');

var App = function(logger) {
    var that = this;
    this.app_name = 'Mock miniserver';
    this.logger = logger;

    this.logger.info(this.app_name + ' started');

    process.on('SIGINT', function () {
        that.logger.info(that.app_name + ' try to stop');
        that.exit(0, 'SIGINT');
    });
    process.on('SIGHUP', function () {
        that.exit(0, 'SIGHUP');
    });
    process.on('SIGTERM', function () {
        that.exit(0, 'SIGTERM');
    });
};

util.inherits(App, events.EventEmitter);

App.prototype.exit = function(code, message) {
    var that = this;
    this.emit('exit', code);

    process.on('exit', function(code) {
        that.logger.info(that.app_name + ' stopped - '+message);
    })
};

module.exports = App;
