import {EncryptionInfoOptions} from "./arguments";
export class EncryptionInfo {
    publicKey: string;
    secret: string;
    isSecretSet = false;
    iv: string;
    salt: string;
    constructor(params ?: EncryptionInfoOptions) {
        for (const v in params) {
            this[v] = params[v];
        }
        if (this.secret !== undefined) {
            this.isSecretSet = true;
        }
    }
    setSecret(secret: string) {
        this.secret = secret;
        this.isSecretSet = true;
    }
    removeSecret() {
        this.secret = undefined;
        this.isSecretSet = false;
    }
    static isEqual(a: EncryptionInfo, b: EncryptionInfo) {
        return a.publicKey === b.publicKey;
    }
}
