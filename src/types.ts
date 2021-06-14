import * as argon2 from "argon2";
import * as stream from 'stream';
import {NetworkInterface} from "./utility/network-interface";
type FindPeersOptions = {
    identity?: IdentityOptions,
    securityLevel?: SecurityLevels,
    verifyTries?: number,
    tryTime?: number,
    encryptionKey?: string,
    hashOptions?: argon2.Options,
    modLength: 1024 | 2048 | 3072 | 4096,
    keyGenGroup?: 'rsa' | 'dsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448',
    aesVersion: 'aes-256-cbc' | 'aes-256-cbc-hmac-sha1' | 'aes-256-cbc-hmac-sha256' | 'aes-256-ccm' | 'aes-256-cfb' | 'aes-256-cfb1' | 'aes-256-cfb8' | 'aes-256-ctr' | 'aes-256-ecb' | 'aes-256-gcm' | 'aes-256-ocb' | 'aes-256-ofb' | 'aes-256-xts',
    oaepHash?: 'sha256' | 'sha1',
    groupName?: 'modp14' | 'modp15' | 'modp16' | 'modp17' | 'modp18',
    autoStartSearch?: boolean,
    shouldMulticastSearch?: boolean,
    serverType?: ServerTypes
    serverPort?: number,
    multicastPort?: number,
    broadCastInterval?: number,
    multiCastTimeout?: number,
    multiCastReSearch?: number,
    shouldReSearch?: boolean,
    searchForever?: boolean,
    enforceValidNode?: boolean,
    shouldPing?: boolean,
    pingInterval?: number,
    pingCount?: number,
    temporaryDisconnect?: number,
    pingMIA?: number,
    pingLimit?: number,
    autoGenId?: boolean,
    whiteList?: string[],
    blackList?: string[],
    privateServerKey?: string,
    certificate?: string,
    genKeypair?: boolean,
    attrs?: any,
    acceptValidClientStreams?: boolean,
    newStreamRejectionTime?: number,
    averageLatency?: number,
    socketIOOptions?: {
        mode?: 'http' | 'https',
        path?: string,
        maxHttpBufferSize?: number,
        allowRequest?: number,
        httpCompression?: boolean,
    }
}

enum ServerTypes {
    tcp,
    http,
    tls,
    https,
    socketIO
}

enum SecurityLevels {
    open,
    hashedKeys,
    encryptedKey,
    generatedKey,
    e2e,
    middleManServer
}

type EncryptionInfoOptions = {
    Identity?: Identity,
    publicKey?: string,
    secret?: string,
    iv?: string,
    salt?: string
}

type IdentityOptions = {
    id?: string,
    ip?: string,
    app?: string,
    enc?: EncryptionInfo
}

type Message = {
    identity: Identity,
    type: string,
    msg?: string
}
type ServerClient = {
    identity: Identity,
    state: 0 | 1 | 2,
    pingCount: number,
    lastPing: number,
    keepAlive: boolean,
    socket?: any
};
type MulticastClient = {
    identity: Identity,
    type: 'ping',
    state: 0 | 1 | 2
};
type TempClient = {
    connectTime: number,
    dataSent: boolean,
    socket: any
};
class Identity {
    public id = '';
    public ip = NetworkInterface.getDefaultIP();
    public app = '';
    public enc = new EncryptionInfo();

    constructor(params ?: IdentityOptions) {
        for (const v in params) {
            // @ts-ignore
            this[v] = params[v];
        }
        this.enc = new EncryptionInfo(this.enc);
    }

    static isEqual(a: Identity, b: Identity) {
        return a.id === b.id && a.ip === b.ip && a.app === b.app && EncryptionInfo.isEqual(a.enc, b.enc);
    }

    getCopy(): Identity {
        return new Identity({
            id: this.id,
            ip: this.ip,
            app: this.app,
            enc: new EncryptionInfo({publicKey: this.enc.publicKey, iv: this.enc.iv, salt: this.enc.salt})
        });
    }
}
class EncryptionInfo {
    publicKey = '';
    secret = '';
    isSecretSet = false;
    iv = '';
    salt = '';

    constructor(params ?: EncryptionInfoOptions) {
        for (const v in params) {
            // @ts-ignore
            this[v] = params[v];
        }
        if (this.secret !== undefined) {
            this.isSecretSet = true;
        }
    }

    static isEqual(a: EncryptionInfo, b: EncryptionInfo) {
        return a.publicKey === b.publicKey;
    }

    setSecret(secret: string) {
        this.secret = secret;
        this.isSecretSet = true;
    }

    removeSecret() {
        this.secret = '';
        this.isSecretSet = false;
    }
}
declare interface FindPeerEvents {
    ready: (status: boolean) => void,
    server_err: (err: Error) => void,
    verify_err: (err: Error) => void,
    multicast_err: (err: Error) => void,
    found_nodes: (nodes: Map<string, ServerClient>) => void,
    echo: (data: { message: string, from: Identity }) => void,
    'stream:create': (stream: stream.Duplex) => void,
    'stream:create:request': (handler: {
        accept: (data?: string, callback?: () => void) => void,
        reject: (reason?: string, callback?: () => void) =>void,
        wait: (waitTime: number, callback?: () => void) => void,
        node: () => { identity: Identity, requestDetails: any }
    }) => void
}
export {
    FindPeersOptions,
    FindPeerEvents,
    Identity,
    EncryptionInfo,
    ServerTypes,
    SecurityLevels,
    EncryptionInfoOptions,
    IdentityOptions,
    Message,
    ServerClient,
    MulticastClient,
    TempClient,
};
