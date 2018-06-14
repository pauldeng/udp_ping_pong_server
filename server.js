'use strict';

const dgram = require('dgram');
const udpServer = dgram.createSocket('udp4');
const printIps = require('./get_ips');
const jsrsasign = require('jsrsasign');
const crc = require('crc');
const sprintf = require("sprintf-js").sprintf;

const curve = 'secp256r1';
const sigalg = 'SHA256withECDSA';

const devices_db = {"00ff171207000037": {"prvkey":"4DD3E638E4BF5F45F17B98A1A960EAB37C80E73A9BE92057D1DBD34DC3EC9CD8", "pubkey":"0482F436D0F7C428D2DDA4FB44174A84AA1D7E310A004BD9E1A1D6777DF59426CCC3E3B39DEEC2D9A6EC831662A77F3BC9EAB7DD67AA15C8CA2F4CFB9D2FA90253"}};
const server_keypair = {prvkey:"ddd6549dabd9564b6ea69c6881441238dca7287aeb3d163802376bf5f5ccc538", pubkey:"0483218cc2199c91fca84865781d41a40154017094764992fd729520e17afcc7107bf2c17216258d71adb83ed34eb4877a5ff83cbf359da9943b470a83bfda8fa2"};

//let reply_msg = Buffer.from('4e4200ff1712070000370102030405', 'hex');

// UDP Server
udpServer.on('listening', () => {
    //Keys stored on server
    console.log('Device EUI64 has Public Key : ' + devices_db['00ff171207000037'].pubkey);
    console.log('FST Server has Private Key  : ' + server_keypair.prvkey);
    //Keys stored on NIC
    //console.log('Device EUI64 has Private Key: ' + devices_db['00ff171207000037'].prvkey);
    //console.log('FST Server has Public Key   : ' + server_keypair.pubkey);

    printIps();

    let address = udpServer.address();
    console.log('UDP Server is up and running at port', address.port);
    console.log('Waiting for messages from device EUI64 00ff171207000037 ...');
    console.log('');
});

let messages = {};

udpServer.on('message', (message, remote) => {
    console.log('UDP Receive', remote.address, remote.port, message.toString('hex'));
    
    let device_eui64 = message.toString('hex').substring(4,20);
    let incoming_msg_payload = message.toString('hex').substring(24, message.toString('hex').length-4);
    let outgoing_msg_payload;

    console.log('Message received from device EUI64', device_eui64, "with payload data", incoming_msg_payload);
    //check if device is in the device_db
    if(devices_db[device_eui64] !== null){
        console.log('  Device EUI64', device_eui64, "is found in server db");

        console.log('  Verify payload data with device Public Key');
        var verifier = new jsrsasign.KJUR.crypto.Signature({"alg": sigalg, "prov": "cryptojs/jsrsa"});
        verifier.init({xy: devices_db[device_eui64].pubkey, curve: curve});
        verifier.updateString(device_eui64);
        var outcome = verifier.verify(incoming_msg_payload);
        
        if(outcome === true){
            console.log("    This is a genuine message from device", device_eui64);
            
            //Sign device EUI64 with server Private key
            console.log('    Sign device EUI64 with server Private key');
            let server_signer = new jsrsasign.KJUR.crypto.Signature({"alg": sigalg});
            server_signer.init({d: server_keypair.prvkey, curve: curve});
            server_signer.updateString(device_eui64);
            outgoing_msg_payload = server_signer.sign();
            console.log('    Outgoing message payload ', outgoing_msg_payload);
        }else{
            console.log("    This is NOT a genuine message from device", device_eui64);
            outgoing_msg_payload = "0404";
            console.log('    Outgoing message payload ', outgoing_msg_payload);
        }
        
    }
    //if device is not in the device_db, server replies not ok
    else{
        console.log('  Device EUI64', device_eui64, 'not found in server db');
        console.log('  Waiting for messages from device EUI64 00ff171207000037');
        console.log('');
    }
    //"4e42" is NBIoT header
    let reply_msg = "4e42" + device_eui64;

    //4 in the middle is the length of Message_Length field
    //4 at last is the length of crc16 modbus
    var reply_msg_len = sprintf('%04x', reply_msg.length + 4 + outgoing_msg_payload.length + 4);
    reply_msg = reply_msg + reply_msg_len + outgoing_msg_payload;

    reply_msg = Buffer.from((reply_msg.toString('hex') + crc.crc16modbus(reply_msg).toString(16)), "hex");

    console.log('UDP Reply  ', remote.address, remote.port, reply_msg.toString('hex'));
    udpServer.send(reply_msg, remote.port, remote.address);
    console.log('');
});

udpServer.bind(2888, '0.0.0.0');
