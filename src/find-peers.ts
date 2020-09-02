import * as net from 'net';
import * as tls from 'tls';
import * as http from 'http';
import * as dgram from 'dgram';
import * as https from 'https';
import {EventEmitter} from 'events';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import * as qs from 'querystring';
import * as axios from 'axios';
import {DiffieHellman} from 'crypto';
import {Identity} from './models/identity';
import {TcpDataBuffer} from './network/tcp-data-buffer';
import {EncryptionInfo} from "./models/encryption-info";
import { FindPeersOptions } from './models/arguments';
import * as process from 'process';
import * as fs from 'fs';
import * as path from 'path';
import {MonitorServer} from "./monitor-server/monitor-server";
let io;
type Message = { identity: Identity, type: string, msg ?: string }
type ServerClient = { identity: Identity, state: 0 | 1 | 2, pingCount: number, lastPing: number, keepAlive: boolean };
type MulticastClient = { identity: Identity, type: 'ping', state: 0 | 1 | 2 };
export class FindPeers extends EventEmitter {
    private identity: Identity = new Identity();
    private securityLevel: 0 | 1 | 2 | 3 | 4 | 5 = 4;
    private verifyTries: number = 3;
    private tryTime: number = 10000;
    private encryptionKey: string;
    private hashOptions: argon2.Options = {
        hashLength: 32,
        memoryCost: 2 ** 16,
        parallelism: 1,
        type: argon2.argon2i
    };
    private modLength: 1024 | 2048 | 3072 | 4096 = 2048;
    private keyGenGroup: 'rsa' | 'dsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448' = 'rsa';
    private publicKey: string;
    private privateKey: string;
    private messageLength: number = 190;
    private messageLengthAssociation = {
        sha128: {
            1024: 86,
            2048: 214,
            3072: 342,
            4096: 470
        },
        sha224: {
            1024: 70,
            2048: 198,
            3072: 326,
            4096: 454
        },
        sha256: {
            1024: 62,
            2048: 190,
            3072: 318,
            4096: 446
        },
        sha384: {
            1024: 30,
            2048: 158,
            3072: 286,
            4096: 414
        },
        sha512: {
            2048: 126,
            3072: 254,
            4096: 382
        },
    };
    private oaepHash ?: 'sha256' | 'sha1' = 'sha256';
    private diffieHellman: DiffieHellman;
    private groupName: 'modp14' | 'modp15' | 'modp16' | 'modp17' | 'modp18' = 'modp15';
    private aesVersion: 'aes-256-cbc' | 'aes-256-cbc-hmac-sha1' | 'aes-256-cbc-hmac-sha256' | 'aes-256-ccm' | 'aes-256-cfb' | 'aes-256-cfb1' | 'aes-256-cfb8' | 'aes-256-ctr' | 'aes-256-ecb' | 'aes-256-gcm' | 'aes-256-ocb' | 'aes-256-ofb' | 'aes-256-xts' = 'aes-256-cbc';
    private autoStartSearch: boolean = true;
    private serverType: 'tcp' | 'http' | 'tls' | 'https' | 'socket' = 'tcp';
    private serverUp: boolean = false;
    private searching: boolean = false;
    private server: net.Server | tls.Server | https.Server;
    private multicastServer: dgram.Socket;
    private serverPort: number = 19235;
    private multicastPort: number = 18235;
    private multicastAddress: string = '224.0.255.255';
    private multicastInterval: NodeJS.Timeout;
    private broadCastInterval: number = 500;
    private multiCastTimeout: number = 60000;
    private multiCastReSearch: number = 300000;
    private shouldReSearch: boolean = false;
    private searchForever: boolean = false;
    private enforceValidNode: boolean = true;
    private shouldPing: boolean = true;
    private pingInterval: number = 1000;
    private pingCount: number = 10;
    private pingLimit: number = 50;
    private temporaryDisconnect: number = 5;
    private pingMIA: number = 10000;
    private useMonitorServer: boolean = false;
    private monitorServerPort: number = 3000;
    private monitorServer: MonitorServer;
    private useSyncServer: boolean = false;
    private syncServerURL: string;
    private syncServerCRUD: string = 'post';
    private syncServerArgs: any;
    private multicastClients = new Map<string, MulticastClient>();
    private serverClients = new Map<string, ServerClient>();
    private whiteList: string[] = [];
    private blackList: string[] = [];
    constructor(options ?: FindPeersOptions) {
        super();
        const omit = ['identity'];
        for (const v in options) {
            if (omit.indexOf(v) === -1) {
                this[v] = options[v];
            }
        }
        // TODO: identity set
        for (const v in options.identity) {
            this.identity[v] = options.identity[v];
        }
        // TODO: options validity checks
        (async() => {
            switch (this.securityLevel) {
                case 1: {
                    // @ts-ignore
                    this.identity.enc.publicKey = await argon2.hash(this.encryptionKey, this.hashOptions);
                    break;
                }
                case 3: {
                    // @ts-ignore
                    const {publicKey, privateKey} = crypto.generateKeyPairSync(this.keyGenGroup, {
                        modulusLength: this.modLength,
                        publicKeyEncoding: {
                            type: 'spki',
                            format: 'pem'
                        },
                        privateKeyEncoding: {
                            type: 'pkcs8',
                            format: 'pem',
                        },
                        cipher: this.aesVersion,
                        passphrase: this.encryptionKey
                    });
                    this.publicKey = publicKey.toString('hex');
                    this.privateKey = privateKey.toString('hex');
                    this.identity.enc.publicKey = this.publicKey;
                    this.messageLength = this.messageLengthAssociation[this.oaepHash][this.modLength];
                    console.log(this.publicKey);
                    break;
                }
                case 4: {
                    this.diffieHellman = crypto.getDiffieHellman(this.groupName);
                    this.diffieHellman.generateKeys();
                    this.publicKey = this.diffieHellman.getPublicKey().toString('hex');
                    this.privateKey = this.diffieHellman.getPrivateKey().toString('hex');
                    this.identity.enc.publicKey = this.publicKey;
                    break;
                }
            }
            if (this.serverType === 'socket') {
                io = await import('socket.io');
            }
            if (this.autoStartSearch) {
                this.search();
            }
        })();
    }
    private search() {
        if (!this.serverUp) {
            this.startServer();
        }
        if (!this.searching) {
            this.searching = true;
            if (this.shouldReSearch) {
                this.startMulticastServer();
                setInterval(() => {
                    this.startMulticastServer();
                }, this.multiCastReSearch);
            } else {
                this.startMulticastServer();
            }
        }
        if (this.useMonitorServer) {
            this.monitorServer = new MonitorServer(this, this.monitorServerPort);
            this.monitorServer.init();
        }
    }
    private startMulticastServer() {
        this.multicastServer = dgram.createSocket({ type: 'udp4' });
        this.multicastServer.bind(this.multicastPort);
        this.multicastServer.on('message', (msg, rinfo) => {
            if (rinfo.address !== this.identity.ip) {
                try {
                    const data: { identity: Identity, type: 'ping', state: 0 } = JSON.parse(msg.toString());
                    if (this.isMessageValid(data) && data.identity.ip !== this.identity.ip) {
                        if (!this.multicastClients.has(data.identity.id) && !this.serverClients.has(data.identity.id)) {
                            data.identity = new Identity(data.identity);
                            this.multicastClients.set(data.identity.id, data);
                            switch (this.securityLevel) {
                                case 0: {
                                    this.multicastClients.get(data.identity.id).state = 2;
                                    const pingBack = this.getPing();
                                    break;
                                }
                                case 1: {
                                    argon2.verify(data.identity.enc.publicKey, this.encryptionKey).then(isValid => {
                                        if (isValid) {
                                            this.multicastClients.get(data.identity.id).state = 1;
                                            this.verifyNode(data).catch(e => this.emit('verify_err', e));
                                        }
                                    }).catch(e => {
                                        this.emit('multicast_err', e);
                                    });
                                    break;
                                }
                                case 2: {
                                    const pingBack = this.getPing();
                                    this.multicastServer.send(pingBack, 0, pingBack.length, this.multicastPort, data.identity.ip);
                                    this.verifyNode(data).catch(e => this.emit('verify_err', e));
                                    break;
                                }
                                case 3: {
                                    const pingBack = this.getPing();
                                    this.multicastServer.send(pingBack, 0, pingBack.length, this.multicastPort, data.identity.ip);
                                    this.verifyNode(data).catch(e => this.emit('verify_err', e));
                                    break;
                                }
                                case 4: {
                                    this.multicastClients.get(data.identity.id).identity.enc.setSecret(this.diffieHellman.computeSecret(this.multicastClients.get(data.identity.id).identity.enc.publicKey, 'hex', 'hex'));
                                    const pingBack = this.getPing();
                                    this.multicastServer.send(pingBack, 0, pingBack.length, this.multicastPort, data.identity.ip);
                                    this.verifyNode(this.multicastClients.get(data.identity.id)).catch(e => this.emit('verify_err', e));
                                    break;
                                }
                            }
                        }
                    }
                } catch (e) {
                    this.emit('multicast_err', e);
                }
            }
        });
        this.multicastServer.on('listening', () => {
            const address = this.multicastServer.address();
            console.log(`server listening on ${address.address}:${address.port} with id ${this.identity.id}`);
            this.multicastServer.addMembership(this.multicastAddress, this.identity.ip);
            this.multicastInterval = setInterval(() => {
                const data = this.getPing();
                this.multicastServer.send(data, 0, data.length, this.multicastPort, this.multicastAddress);
            }, this.broadCastInterval);
        });
        this.multicastServer.on('error', err => {
            this.emit('multicast_err', err);
        });
        if (!this.searchForever) {
            setTimeout(() => {
                clearInterval(this.multicastInterval);
                this.multicastServer.close();
                for (const v of this.multicastClients.entries()) {
                    if (v[1].state === 2) {
                        this.serverClients.set(v[0], { identity: v[1].identity, state: v[1].state, pingCount: 0, lastPing: new Date().getTime(), keepAlive: true });
                    }
                }
                this.multicastClients.clear();
                this.emit('found-nodes', this.serverClients);
            }, this.multiCastTimeout);
        }
    }
    private async verifyNode(node: { identity: Identity, type: string }) {
        console.log('verifying:', node.identity.id, node.identity.ip);
        const copyNode =  node.identity.getCopy();
        if (copyNode.enc.isSecretSet) {
            copyNode.enc.removeSecret();
        }
        let tries = 0;
        let successful = false;
        while (tries < this.verifyTries && !successful) {
            try {
                switch (this.serverType) {
                    case 'tcp': {
                        await new Promise((resolve, reject) => {
                            let canAccept = false;
                            const recieveBuffer = new TcpDataBuffer();
                            const validityKey = crypto.randomBytes(64).toString('hex');
                            console.log('sending verify request to: ', node.identity.ip);
                            const client = net.createConnection({ host: node.identity.ip, port: this.serverPort }, () => {
                                const { enc, msg } = this.encrypt(JSON.stringify({ sender: this.identity, receiver: copyNode, key: validityKey }), this.securityLevel === 4 || this.securityLevel === 3 ? node.identity : undefined);
                                const copy = this.identity.getCopy();
                                copy.enc.salt = enc.salt;
                                copy.enc.iv = enc.iv;
                                TcpDataBuffer.writeClient(client, this.message(msg, copy,'verify'));
                            });
                            client.on('error', err => {
                                console.log(err);
                                reject(err);
                            });
                            client.on('close', hadErr => {
                                if (hadErr) {
                                    reject(hadErr);
                                }
                            });
                            client.on('data', data => {
                                recieveBuffer.readBytes(data);
                            });
                            recieveBuffer.on('done', (data: Buffer) => {
                                const parsed: Message = JSON.parse(data.toString());
                                parsed.identity = new Identity(parsed.identity);
                                parsed.identity.enc.setSecret(this.multicastClients.get(parsed.identity.id).identity.enc.secret);
                                const decryptedData: { sender: Identity, receiver: Identity, key: string } = JSON.parse(this.decrypt(parsed.msg, parsed.identity));
                                if (decryptedData.key === validityKey && Identity.isEqual(decryptedData.sender, node.identity) && Identity.isEqual(decryptedData.receiver, this.identity)) {
                                    this.multicastClients.get(node.identity.id).state = 2;
                                    client.end();
                                    successful = true;
                                    console.log('node verified at callback: ', node.identity.id);
                                    resolve();
                                }
                            });
                            setTimeout(() => {
                                client.end();
                            }, this.tryTime);
                        });
                        break;
                    }
                }
            } catch (e) {
            }
            tries++;
        }
    }
    private isMessageValid(data: any): boolean {
        if (!data.hasOwnProperty('identity')) {
            return false;
        }
        if (!data.hasOwnProperty('type')) {
            return false;
        }
        if (typeof data.type !== 'string') {
            return false;
        }
        if (data.type.length === 0) {
            return false;
        }
        if (!data.identity.hasOwnProperty('id')) {
            return false;
        }
        if (!data.identity.hasOwnProperty('ip')) {
            return false;
        }
        if (!data.identity.hasOwnProperty('app')) {
            return false;
        }
        if ((this.securityLevel === 4 || this.securityLevel === 3) && data.identity.hasOwnProperty('publicKey') && typeof data.identity.enc.publicKey !== 'string') {
            return false;
        }
        if (typeof data.identity.id !== 'string') {
            return false;
        }
        if (typeof data.identity.ip !== 'string') {
            return false;
        }
        return typeof data.identity.app === 'string';
    }
    private getPing(): Buffer {
        return Buffer.from(JSON.stringify({ identity: this.identity, type: 'ping', state: 0 }));
    }
    public echo(message: string = 'echo', omit ?: string[]): void {
        for (const v of this.serverClients.entries()) {
            if (omit === undefined || (omit && omit.indexOf(v[0]) === -1)) {
                this.messageClient(v[0], message);
            }
        }
    }
    public async messageClient(id: string, message: string): Promise<boolean> {
        if (this.serverClients.has(id)) {
            const node = this.serverClients.get(id);
            if (this.enforceValidNode && node.state !== 2) {
                return false;
            } else {
                try {
                    switch (this.serverType) {
                        case "tcp": {
                            const client = net.createConnection({ host: node.identity.ip, port: this.serverPort }, () => {
                                const { enc, msg } = this.encrypt(message, this.securityLevel === 4 || this.securityLevel === 3 ? node.identity : undefined);
                                const copy = this.identity.getCopy();
                                copy.enc.salt = enc.salt;
                                copy.enc.iv = enc.iv;
                                TcpDataBuffer.writeClient(client, this.message(msg, copy,'echo'), () => true, true);
                            });
                            break;
                        }
                    }
                } catch (e) {
                    return false;
                }
            }
        } else {
            return false;
        }
    }
    public getClients(): Map<string, ServerClient> {
        return this.serverClients;
    }
    private message(msg: string | Buffer, identity: Identity, type: string = 'msg'): Buffer {
        if (typeof msg === 'string') {
            return Buffer.from(JSON.stringify({ msg, identity, type }));
        }
        return Buffer.from(JSON.stringify({ msg: msg.toString(), identity: this.identity, type }));
    }
    private decrypt(data: string, identity: Identity): string {
        let msg: string = '';
        switch (this.securityLevel) {
            case 0:
            case 1: {
                msg = data;
                break;
            }
            case 2: {
                const hash = crypto.pbkdf2Sync(this.encryptionKey, identity.enc.salt, this.modLength, 32, 'sha512');
                const encryptedText = Buffer.from(data, 'hex');
                const decipher = crypto.createDecipheriv(this.aesVersion, hash, Buffer.from(identity.enc.iv, 'hex'));
                const decrypted = decipher.update(encryptedText);
                msg = Buffer.concat([decrypted, decipher.final()]).toString();
                break;
            }
            case 3: {
                const message: { msg: string[], signature: string[] } = JSON.parse(data);
                const decrypted: Buffer[] = [];
                for (const [idx, v] of message.msg.entries()) {
                    const temp = Buffer.from(v, 'hex');
                    decrypted.push(crypto.privateDecrypt({ key: this.privateKey, oaepHash: this.oaepHash }, temp));
                    const verify = crypto.createVerify(this.oaepHash);
                    verify.write(decrypted[idx].toString());
                    verify.end();
                    if (!verify.verify(identity.enc.publicKey, message.signature[idx], 'hex')) {
                        return null;
                    }
                }
                msg = Buffer.concat(decrypted).toString();
                break;
            }
            case 4: {
                if (identity.enc.isSecretSet) {
                    const hash = crypto.pbkdf2Sync(identity.enc.secret, identity.enc.salt, this.modLength, 32, 'sha512');
                    const encryptedText = Buffer.from(data, 'hex');
                    const decipher = crypto.createDecipheriv(this.aesVersion, hash, Buffer.from(identity.enc.iv, 'hex'));
                    const decrypted = decipher.update(encryptedText);
                    msg = Buffer.concat([decrypted, decipher.final()]).toString();
                }
                break;
            }
        }
        return msg;
    }
    private encrypt(data: string, secretIdentity ?: Identity): { enc: EncryptionInfo, msg: string } {
        let msg: string = '';
        let enc: EncryptionInfo = new EncryptionInfo();
        switch (this.securityLevel) {
            case 0:
            case 1: {
                msg = data;
                break;
            }
            case 2: {
                enc = new EncryptionInfo({ salt: crypto.randomBytes(16).toString('hex'), iv: crypto.randomBytes(16).toString('hex') });
                const hash = crypto.pbkdf2Sync(this.encryptionKey, enc.salt, this.modLength, 32, 'sha512');
                const cipher = crypto.createCipheriv(this.aesVersion, hash, Buffer.from(enc.iv, 'hex'));
                const encrypted = cipher.update(data);
                msg = Buffer.concat([encrypted, cipher.final()]).toString('hex');
                break;
            }
            case 3: {
                enc = new EncryptionInfo({ publicKey: secretIdentity.enc.publicKey });
                // msg = 'Lorem ipsum dolor sit amet, onsectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum';
                const message = Buffer.from(data);
                let len = message.length;
                let start = 0, end = this.messageLength, size = this.messageLength;
                const encryptedDataArray: string[] = [];
                const signatureArray: string[] = [];
                do {
                    let newMessage = message.slice(start, (end >= message.length ? message.length : end));
                    start += this.messageLength;
                    end += this.messageLength;
                    len -= this.messageLength;
                    encryptedDataArray.push(crypto.publicEncrypt({ key: secretIdentity.enc.publicKey, oaepHash: this.oaepHash }, newMessage).toString('hex'));
                    const sign = crypto.createSign(this.oaepHash);
                    sign.write(newMessage);
                    sign.end();
                    signatureArray.push(sign.sign(this.privateKey, 'hex'));
                } while(len > size);
                if(len > 0) {
                    let newMessage = Buffer.from(message.slice(start));
                    encryptedDataArray.push(crypto.publicEncrypt({ key: secretIdentity.enc.publicKey, oaepHash: this.oaepHash }, newMessage).toString('hex'));
                    const sign = crypto.createSign(this.oaepHash);
                    sign.write(newMessage);
                    sign.end();
                    signatureArray.push(sign.sign(this.privateKey, 'hex'));
                }
                msg = JSON.stringify({ msg: encryptedDataArray, signature: signatureArray });
                break;
            }
            case 4: {
                enc = new EncryptionInfo({ publicKey: secretIdentity.enc.publicKey, salt: crypto.randomBytes(16).toString('hex'), iv: crypto.randomBytes(16).toString('hex') });
                const hash = crypto.pbkdf2Sync(secretIdentity.enc.secret, enc.salt, this.modLength, 32, 'sha512');
                const cipher = crypto.createCipheriv(this.aesVersion, hash, Buffer.from(enc.iv, 'hex'));
                const encrypted = cipher.update(data);
                msg = Buffer.concat([encrypted, cipher.final()]).toString('hex');
                break;
            }
        }
        return { enc, msg };
    }
    private requestHandler(payload: Buffer, client: net.Socket) {
        try {
            let data: Message = JSON.parse(payload.toString());
            const msg = data.msg;
            switch (data.type) {
                case 'verify': {
                    if (this.securityLevel === 4) {
                        data.identity = this.multicastClients.get(data.identity.id).identity;
                        data.identity.enc.salt = JSON.parse(payload.toString()).identity.enc.salt;
                        data.identity.enc.iv = JSON.parse(payload.toString()).identity.enc.iv;
                    }
                    console.log('tcp request from: ', data.identity.id, 'for verification');
                    const decrypted: { sender: Identity, receiver: Identity, key: string } = JSON.parse(this.decrypt(msg, data.identity));
                    if (this.multicastClients.has(data.identity.id) && this.multicastClients.get(data.identity.id).state !== 2) {
                        const copy = this.multicastClients.get(data.identity.id).identity.getCopy();
                        if (Identity.isEqual(copy, decrypted.sender) && Identity.isEqual(decrypted.receiver, this.identity)) {
                            const { enc, msg } = this.encrypt(JSON.stringify({ sender: this.identity, receiver: copy, key: decrypted.key }), this.securityLevel === 4 || this.securityLevel === 3 ? this.multicastClients.get(data.identity.id).identity : undefined);
                            const copyIn = this.identity.getCopy();
                            copyIn.enc.salt = enc.salt;
                            copyIn.enc.iv = enc.iv;
                            this.multicastClients.get(data.identity.id).state = 2;
                            console.log('node verified at handler: ', data.identity.id);
                            TcpDataBuffer.writeClient(client, this.message(msg, copyIn,'verify'), undefined, true);
                        }
                    } else {
                        client.end();
                    }
                    break;
                }
                case 'echo': {
                    if (this.securityLevel === 4) {
                        data.identity = this.serverClients.get(data.identity.id).identity;
                        data.identity.enc.salt = JSON.parse(payload.toString()).identity.enc.salt;
                        data.identity.enc.iv = JSON.parse(payload.toString()).identity.enc.iv;
                    }
                    console.log('tcp request from: ', data.identity.id, 'for echo');
                    this.emit('echo', { message: this.decrypt(msg, data.identity), from: data.identity });
                    break;
                }
                case 'ping': {
                    if (this.securityLevel === 4) {
                        data.identity = this.serverClients.get(data.identity.id).identity;
                        data.identity.enc.salt = JSON.parse(payload.toString()).identity.enc.salt;
                        data.identity.enc.iv = JSON.parse(payload.toString()).identity.enc.iv;
                    }
                    console.log('tcp request from: ', data.identity.id, 'for ping');
                    const parsed: { key: string, keepAlive: boolean } = JSON.parse(this.decrypt(msg, data.identity));
                    if (this.serverClients.has(data.identity.id)) {
                        const { enc, msg } = this.encrypt(JSON.stringify({ key: parsed.key, keepAlive: this.serverClients.get(data.identity.id).keepAlive }), this.securityLevel === 4 || this.securityLevel === 3 ? this.serverClients.get(data.identity.id).identity : undefined);
                        const copyIn = this.identity.getCopy();
                        copyIn.enc.salt = enc.salt;
                        copyIn.enc.iv = enc.iv;
                        TcpDataBuffer.writeClient(client, this.message(msg, copyIn,'ping'), undefined, true);
                    } else {
                        client.end();
                    }
                    break;
                }
            }
        } catch (e) {
            this.emit('server_err', e);
        }
    }
    private startServer() {
        // TODO: other server types
        switch (this.serverType) {
            case 'tcp': {
                this.server = net.createServer(client => {
                    let tcpDataBuffer = new TcpDataBuffer();
                    client.on('data', data => {
                        try {
                            tcpDataBuffer.readBytes(data);
                        } catch (e) {
                            client.destroy();
                            this.emit('server_err', e);
                        }
                    });
                    tcpDataBuffer.on('done', (data: Buffer) => {
                        this.requestHandler(data, client);
                    });
                    client.on('close', err => {
                        if (err) {
                            this.emit('server_err', err);
                        }
                    });
                    client.on('error', err => {
                        this.emit('server_err', err);
                    });
                }).listen(this.serverPort, this.identity.ip, () => {
                    this.serverUp = true;
                    this.emit('server_up', true);
                });
                this.server.on('error', err => {
                    this.emit('server_err', err);
                });
                break;
            }
            case 'http': {

                break;
            }
            case 'https': {

                break;
            }
            case 'tls': {

                break;
            }
            case 'socket': {

                break;
            }
        }
        if (this.shouldPing) {
            setInterval(() => {
                for (const v of this.serverClients) {
                    if (v[1].keepAlive) {
                        const node = v[1];
                        try {
                            switch (this.serverType) {
                                case "tcp": {
                                    const client = net.createConnection({ host: node.identity.ip, port: this.serverPort }, () => {
                                        const key = crypto.randomBytes(32).toString('hex');
                                        const { enc, msg } = this.encrypt(JSON.stringify({ key, keepAlive: false }), this.securityLevel === 4 || this.securityLevel === 3 ? node.identity : undefined);
                                        const copyIn = this.identity.getCopy();
                                        copyIn.enc.salt = enc.salt;
                                        copyIn.enc.iv = enc.iv;
                                        TcpDataBuffer.writeClient(client, this.message(msg, copyIn,'ping'), () => {
                                            const buffer = new TcpDataBuffer();
                                            client.on('data', (data) => {
                                                buffer.readBytes(data);
                                            });
                                            buffer.on('done', (payload) => {
                                                client.end();
                                                const data: Message = JSON.parse(payload.toString());
                                                data.identity = new Identity(data.identity);
                                                data.identity.enc.setSecret(this.serverClients.get(data.identity.id).identity.enc.secret);
                                                const parsed: { key: string, keepAlive: boolean } = JSON.parse(this.decrypt(data.msg, data.identity));
                                                if (parsed.key === key) {
                                                    this.serverClients.get(v[0]).keepAlive = parsed.keepAlive;
                                                    this.serverClients.get(v[0]).lastPing = new Date().getTime();
                                                    console.log(v[0], 'updated via ping at', new Date());
                                                }
                                            });
                                        }, false);
                                    });
                                    client.on('error', (err) => {
                                        this.handlePing(node, v[0]);
                                    });
                                    client.on('close', (err) => {
                                        if (err) {
                                            this.handlePing(node, v[0]);
                                        }
                                    });;
                                    client.on('timeout', () => {
                                        this.handlePing(node, v[0]);
                                    });
                                    break;
                                }
                            }
                        } catch (e) {
                            this.handlePing(node, v[0]);
                        }
                    }
                }
            }, this.pingInterval);
        }
    }
    private handlePing(node: ServerClient, id: string) {
        if (node.pingCount > this.pingCount || node.lastPing > new Date().getTime() + this.pingMIA) {
            this.serverClients.get(id).state = 0;
            this.serverClients.get(id).pingCount++;
        } else if (node.pingCount <= this.temporaryDisconnect) {
            this.serverClients.get(id).pingCount++;
        } else if (node.pingCount <= this.pingCount) {
            this.serverClients.get(id).pingCount++;
            this.serverClients.get(id).state = 1;
        }
        if (node.pingCount > 50) {
            this.serverClients.get(id).keepAlive = false;
        }
    }
    public getIdentity() {
        return this.identity.getCopy();
    }
}
