import {address, isV4Format} from 'ip';
import {networkInterfaces} from 'os';

export class NetworkInterface {
    static localNames = ['127.0.0.1', '0.0.0.0', 'localhost', '::1'];

    static getDefaultIP(): string {
        const fromLibIP = address();
        const interfaces = networkInterfaces();
        if (interfaces) {
            for (const card of Object.keys(interfaces)) {
                // @ts-ignore
                for (const cardInterface of interfaces[card]) {
                    if (NetworkInterface.localNames.indexOf(cardInterface.address) === -1 && isV4Format(cardInterface.address)) {
                        return cardInterface.address;
                    }
                }
            }
        }
        return fromLibIP;
    }
}
