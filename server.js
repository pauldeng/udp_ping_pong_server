'use strict';

const dgram = require('dgram');
const udpServer = dgram.createSocket('udp4');
const printIps = require('./get_ips');

// UDP Server
udpServer.on('listening', () => {
    printIps();

    let address = udpServer.address();
    console.log('UDP Server is up and running at port', address.port);
});

let messages = {};

udpServer.on('message', (message, remote) => {
    console.log('UDP Receive', remote.address, remote.port, message.toString('hex'));

    //if (message.toString('ascii') === 'ping') {
        let reply_msg = Buffer.from('4e4200ff1712070000370102030405fb59', 'hex');
        console.log('UDP Reply  ', remote.address, remote.port, reply_msg.toString('hex'));
        udpServer.send(reply_msg, remote.port, remote.address);
    //}
});

udpServer.bind(2888, '0.0.0.0');
