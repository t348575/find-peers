import {EventEmitter} from "events";
import * as http from 'http';
import * as net from 'net';
import * as tls from 'tls';
import {Socket} from "dgram";

export class DataBuffer extends EventEmitter {
    private state: 0 | 1 | 2 | 3 = 0;
    private dataMode: 0 | 1 = 0;
    private payload: Buffer = null;
    private payloadSize: number = -1;
    private index: number = 0;

    static createHeader(size: number): Buffer {
        const header = Buffer.allocUnsafe(4);
        header.writeUInt32BE(size, 0);
        return header;
    }

    static isSocketIO(socket: any): boolean {
        return !(socket instanceof net.Socket) && !(socket instanceof http.ServerResponse) && !(socket instanceof tls.TLSSocket);

    }

    static writeClient(client: Socket | http.ServerResponse | http.ClientRequest | any, data: string | Buffer, callback ?: Function, autoClose: boolean | string = false): void {
        if (DataBuffer.isSocketIO(client)) {
            client.emit(autoClose, data);
        } else {
            client.write(DataBuffer.createHeader(data.length), (err) => {
                if (err) {
                    // console.log(err);
                } else {
                    client.write(data, err1 => {
                        if (err1) {
                            // console.log(err1);
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
}
