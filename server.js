'use strict';

const dgram = require('dgram');
const udpServer = dgram.createSocket('udp4');
const printIps = require('./get_ips');
const jsrsasign = require('jsrsasign');
const crc = require('crc');

const curve = 'secp256r1';
const sigalg = 'SHA256withECDSA';

const devices_db = {"00ff171207000037": {"prvkey":"4DD3E638E4BF5F45F17B98A1A960EAB37C80E73A9BE92057D1DBD34DC3EC9CD8", "pubkey":"0482F436D0F7C428D2DDA4FB44174A84AA1D7E310A004BD9E1A1D6777DF59426CCC3E3B39DEEC2D9A6EC831662A77F3BC9EAB7DD67AA15C8CA2F4CFB9D2FA90253"}};
const server_keypair = {prvkey:"ddd6549dabd9564b6ea69c6881441238dca7287aeb3d163802376bf5f5ccc538", pubkey:"0483218cc2199c91fca84865781d41a40154017094764992fd729520e17afcc7107bf2c17216258d71adb83ed34eb4877a5ff83cbf359da9943b470a83bfda8fa2"};

let reply_msg = Buffer.from('4e4200ff1712070000370102030405', 'hex');

// UDP Server
udpServer.on('listening', () => {
    printIps();

    let address = udpServer.address();
    console.log('UDP Server is up and running at port', address.port);
});

let messages = {};

udpServer.on('message', (message, remote) => {
    console.log('UDP Receive', remote.address, remote.port, message.toString('hex'));

    //check if device is in the device_db
    if(devices_db['00ff171207000037'] !== null){
        //gen key
        console.log('gen key');
        const ec = new jsrsasign.KJUR.crypto.ECDSA({"curve": curve});
        const keypair = ec.generateKeyPairHex();
        console.log('generated private ', keypair.ecprvhex);
        console.log('generated public  ', keypair.ecpubhex);
        console.log('');

        //sign device message
        console.log('sign message with device private key');
        //var prvkey = "4DD3E638E4BF5F45F17B98A1A960EAB37C80E73A9BE92057D1DBD34DC3EC9CD8";
        let prvkey = devices_db['00ff171207000037'].prvkey;
        let msg1 = Buffer.from("00ff171207000037", "hex");
        let sig = new jsrsasign.KJUR.crypto.Signature({"alg": sigalg});
        sig.init({d: prvkey, curve: curve});
        sig.updateString(msg1.toString('hex'));
        let sigValueHex = sig.sign();
        console.log('message     ', msg1.toString('hex'));
        console.log('sigValueHex ', sigValueHex);
        console.log('');

        //verify message
        console.log('verify message with device public key');
        //var pubkey = "0482F436D0F7C428D2DDA4FB44174A84AA1D7E310A004BD9E1A1D6777DF59426CCC3E3B39DEEC2D9A6EC831662A77F3BC9EAB7DD67AA15C8CA2F4CFB9D2FA90253";
        let pubkey = devices_db['00ff171207000037'].pubkey;
        //var sigval = "304502201ff707247352fb5b6428f06456a90114c579088d699205cb6eda155ee9497189022100fd438a2468a3a034856e47942ad4ba1a9c4a71e1aaefd02cd04c5ad6c3e6e182";
        let sigval = sigValueHex;
        console.log('sigval ', sigval);
        let verify = new jsrsasign.KJUR.crypto.Signature({"alg": sigalg, "prov": "cryptojs/jsrsa"});
        verify.init({xy: pubkey, curve: curve});
        verify.updateString(msg1.toString('hex'));
        let result = verify.verify(sigval);
        console.log('verify ', result);
        console.log('');


        console.log('sign message with server private key');
        console.log('message     ', msg1.toString('hex'));
        let server_prvkey = server_keypair.prvkey;
        let server_sign = new jsrsasign.KJUR.crypto.Signature({"alg": sigalg});
        server_sign.init({d: server_prvkey, curve: curve});
        server_sign.updateString(msg1.toString('hex'));
        let server_sigValueHex = server_sign.sign();
        console.log('server_sigValueHex ', server_sigValueHex);
        
    }
    //if device is not in the device_db, server replies not ok
    else{
        console.log("not found");
        
        // create a error command
    }

    console.log("calculate replay message crc");
    console.log('reply_msg ', reply_msg.toString('hex'));
    console.log('crc16 ', crc.crc16modbus(reply_msg).toString(16));
    
    reply_msg = Buffer.from((reply_msg.toString('hex') + crc.crc16modbus(reply_msg).toString(16)), "hex");
    console.log("reply_msg ", reply_msg.toString('hex'));
    
    //let reply_msg = Buffer.from('4e4200ff1712070000370102030405fb59', 'hex');
    console.log('UDP Reply  ', remote.address, remote.port, reply_msg.toString('hex'));
    udpServer.send(reply_msg, remote.port, remote.address);
    console.log('');
});

udpServer.bind(2888, '0.0.0.0');
