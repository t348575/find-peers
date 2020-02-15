const dgram = require('dgram');
const net = require('net');
const ip = require('ip');
const bcrypt = require('bcryptjs');
let identity = {};
let peerSet = [];
let pending = [];
let server, socket, socketCall;
let SECRET_KEY, SECRET_KEY_HASH;
setIdentity = (options) => {
    identity.name =  '_' + Math.random().toString(36).substr(2, 9);
    identity.ip = ip.address();
    for(let v in options) {
        if(!(typeof v === 'object' && v !== null)) {
            if(v === 'app' && identity.hasOwnProperty(v)) {
                identity.app = options[v];
            }
            if(v === 'name' && identity.hasOwnProperty(v)) {
                identity.name = options[v];
            }
        }
    }
};
tcpServer = function (PORT) {
    server = net.createServer((client) => {
        client.on('data', (data) => {
            try {
                data = JSON.parse(data.toString());
                if(bcrypt.compareSync(SECRET_KEY, data.key) && data.app === identity.app && searchPeers(data).length === 0) {
                    removePendingPeers(data);
                    peerSet.push(data);
                    // console.log(`${data.ip} has been added to peerSet`);
                    sendConnection(data.ip, PORT, SECRET_KEY_HASH);
                }
            } catch(err) {
                console.log('Error!');
                console.log(err.stack);
            }
        });
    }).listen(PORT);
    server.on("error", (err) => {
        console.log("Caught flash policy server socket error: ");
        console.log(err.stack);
    });
};
searchPeers = (data) => {
    return peerSet.filter(obj => obj.name === data.name);
};
searchPendingPeers = (data) => {
    return pending.filter(obj => obj.name === data.name);
};
removePendingPeers = (data) => {
    pending = pending.filter(obj => obj.name !== data.name);
};
getPeerSet = () => { return peerSet; };
sendConnection = (IP, PORT) => {
    const client = net.createConnection({ host: IP, port: PORT }, function () {
        client.write(JSON.stringify({ name: identity.name, ip: identity.ip, app: identity.app, key: SECRET_KEY_HASH }), () => client.end());
    });
    client.on("error", (err) => {
        console.log("Caught flash policy server socket error: ");
        console.log(err.stack);
    });
};
findPeers = (MULTICAST_ADDR, MULTICAST_PORT, TCP_PORT, _SECRET_KEY, SEARCH_TIME) => {
    tcpServer(TCP_PORT, SECRET_KEY);
    SECRET_KEY = _SECRET_KEY;
    SECRET_KEY_HASH = bcrypt.hashSync(SECRET_KEY, 8);
    socket = dgram.createSocket({ type: "udp4" });
    socket.bind(MULTICAST_PORT, identity.ip, () => socket.setBroadcast(true));
    socket.on('listening', () => {
        socket.addMembership(MULTICAST_ADDR);
        socketCall = setInterval(() => {
            socket.send(JSON.stringify(identity), 0, JSON.stringify(identity).length, MULTICAST_PORT, MULTICAST_ADDR);
        }, 1000)
    });
    socket.on("message", (data) => {
        data = JSON.parse(data);
        if(data.ip && data.name && data.name !== identity.name) {
            let spl = searchPeers(data).length;
            let sppl = searchPendingPeers(data).length;
            if(spl === 0 && sppl === 0) {
                // console.log(`Added ${data.name} from ${data.ip} to pending list`);
                pending.push(data);
                sendConnection(data.ip, TCP_PORT, SECRET_KEY_HASH);
            } else if(spl === 0 && sppl !== 0) {
                sendConnection(data.ip, TCP_PORT, SECRET_KEY_HASH);
            }
        }
    });
    return new Promise((resolve) => {
        setTimeout(() => {
            server.close();
            clearInterval(socketCall);
            socket.close();
            resolve();
        }, SEARCH_TIME * 1000);
    });
};
module.exports = { setIdentity, findPeers , getPeerSet };
