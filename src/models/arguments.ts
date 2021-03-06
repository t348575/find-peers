import {Identity} from "./identity";
import * as argon2 from "argon2";
import {EncryptionInfo} from "./encryption-info";

export type FindPeersOptions = {
    identity?: IdentityOptions,
    securityLevel?: securityLevels,
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
    serverType?: serverTypes
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
    socketIOOptions?: {
        mode?: 'http' | 'https',
        path?: string,
        maxHttpBufferSize?: number,
        allowRequest?: number,
        httpCompression?: boolean,
    }
}

export enum serverTypes {
    tcp,
    http,
    tls,
    https,
    socketIO
}

export enum securityLevels {
    open,
    hashedKeys,
    encryptedKey,
    generatedKey,
    e2e,
    middleManServer
}

export type EncryptionInfoOptions = {
    Identity?: Identity,
    publicKey?: string,
    secret?: string,
    iv?: string,
    salt?: string
}

export type IdentityOptions = {
    id?: string,
    ip?: string,
    app?: string,
    enc?: EncryptionInfo
}
