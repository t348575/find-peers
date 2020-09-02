import {Socket} from "net";
import {EventEmitter} from "events";

export class TcpDataBuffer extends EventEmitter {
    private state: 0 | 1 | 2 | 3 = 0;
    private dataMode: 0 | 1 = 0;
    private payload: Buffer = null;
    private payloadSize: number = -1;
    private index: number = 0;
    public readBytes(data: Buffer): void {
        switch (this.state) {
            case 0: {
                this.payloadSize = data.readUInt32BE(0);
                this.payload = Buffer.allocUnsafe(this.payloadSize);
                data.copy(this.payload, 0, 4);
                this.index = data.length - 4;
                this.state = 1;
                break;
            }
            case 1: {
                switch (this.dataMode) {
                    case 0: {
                        data.copy(this.payload, this.index);
                        this.index += data.length;
                        if (this.index === this.payloadSize) {
                            this.emit('done', this.payload);
                            this.state = 0;
                            this.payload = null;
                            this.payloadSize = -1;
                            this.index = 0;
                        }
                        break;
                    }
                    case 1: {
                        break;
                    }
                }
                break;
            }
            case 3: {
                break;
            }
        }
    }
    public getPayload(): Buffer {
        return this.payload;
    }
    public toString(encoding: 'utf8' | 'hex' | 'binary' | 'base64' = 'utf8'): string {
        return this.payload.toString(encoding);
    }
    public isPayloadReady(): boolean {
        return this.payloadSize === -1 ? false : this.payloadSize === this.payload.length;
    }
    public getMode(): 0 | 1 | 2 | 3 {
        return this.state;
    }
    public distance(): number {
        return this.payloadSize - this.payload.length;
    }
    static createHeader(size: number): Buffer {
        const header = Buffer.allocUnsafe(4);
        header.writeUInt32BE(size, 0);
        return header;
    }
    static writeClient(client: Socket, data: string | Buffer, callback ?: Function, autoClose = false) {
        // console.log('datalen', data.length);
        client.write(TcpDataBuffer.createHeader(data.length), (err) => {
            if (err) {
                // TODO error
            } else {
                client.write(data, err1 => {
                    if (err1) {
                        // TODO error
                    } else {
                        if (autoClose) {
                            client.end();
                        }
                        if (callback) {
                            callback();
                        }
                    }
                });
            }
        });
    }
}
