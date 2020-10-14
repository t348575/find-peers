import {NetworkInterface} from "../network/network-interface";
import {EncryptionInfo} from "./encryption-info";
import {IdentityOptions} from "./arguments";

export class Identity {
    public id = '';
    public ip = NetworkInterface.getDefaultIP();
    public app = '';
    public enc = new EncryptionInfo();

    constructor(params ?: IdentityOptions) {
        for (const v in params) {
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
