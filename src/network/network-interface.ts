import { isV4Format, isV6Format, address } from 'ip';
import { networkInterfaces } from 'os';
export class NetworkInterface {
    static localNames = ['127.0.0.1', '0.0.0.0', 'localhost', '::1'];
    static getDefaultIP(): string {
        const fromLibIP = address();
        const interfaces = networkInterfaces();
        for (const card of Object.keys(interfaces)) {
            for (const cardInterface of interfaces[card]) {
                if (NetworkInterface.localNames.indexOf(cardInterface.address) === -1 && isV4Format(cardInterface.address)) {
                    return cardInterface.address;
                }
            }
        }
        return fromLibIP;
    }
}
