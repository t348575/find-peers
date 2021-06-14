import {EventEmitter} from 'events';
type Arguments<T> = [T] extends [(...args: infer U) => any] ? U : [T] extends [void] ? [] : [T]
interface TypedEvents<Events> {
    addListener<E extends keyof Events> (event: E, listener: Events[E]): this,
    on<E extends keyof Events> (event: E, listener: Events[E]): this,
    once<E extends keyof Events> (event: E, listener: Events[E]): this,
    prependListener<E extends keyof Events> (event: E, listener: Events[E]): this,
    prependOnceListener<E extends keyof Events> (event: E, listener: Events[E]): this,
    off<E extends keyof Events>(event: E, listener: Events[E]): this,
    removeAllListeners<E extends keyof Events> (event?: E): this,
    removeListener<E extends keyof Events> (event: E, listener: Events[E]): this,
    emit<E extends keyof Events> (event: E, ...args: Arguments<Events[E]>): boolean,
    eventNames (): (keyof Events | string | symbol)[],
    rawListeners<E extends keyof Events> (event: E): Function[],
    listeners<E extends keyof Events> (event: E): Function[],
    listenerCount<E extends keyof Events> (event: E): number,
    getMaxListeners (): number,
    setMaxListeners (maxListeners: number): this
}
interface InternalEventTypes {
    global: (...args: any) => any,
    stream: (mode: 'accept' | 'reject' | 'wait', reason?: string) => void,
    verify: () => void
}
type listenHandler = Map<string, Function>;
class InternalEvents extends (EventEmitter as new () => TypedEvents<InternalEventTypes>) {
    private readonly streamListeners: listenHandler  = new Map();
    private readonly verifyListeners: listenHandler = new Map();
    constructor() {
        super();
    }
    listener<E extends keyof InternalEventTypes>(event: E, args: string[], listener: InternalEventTypes[E], ): this {
        switch (event) {
            case "stream": {
                if (this.streamListeners.has(`${event}:${args[0]}:${args[1]}`)) {
                    throw new Error(`${event}:${args[0]}:${args[1]} already exists!`);
                }
                this.streamListeners.set(`${event}:${args[0]}:${args[1]}`, listener);
                return this.addListener<any>(`${event}:${args[0]}:${args[1]}`, listener);
            }
            case "verify": {
                if (this.verifyListeners.has(`${event}:${args[0]}`)) {
                    throw new Error(`${event}:${args[0]}:${args[1]} already exists!`);
                }
                this.verifyListeners.set(`${event}:${args[0]}`, listener);
                return this.addListener<any>(`${event}:${args[0]}`, listener);
            }
            default: {
                return this.addListener<E>(event, listener);
            }
        }
    }
    delete<E extends keyof InternalEventTypes>(event: E, args: string[], listener?: InternalEventTypes[E]) {
        switch (event) {
            case "stream": {
                if (!this.streamListeners.has(`${event}:${args[0]}:${args[1]}`)) {
                    throw new Error(`${event}:${args[0]}:${args[1]} does not exist!`);
                }
                const func = this.streamListeners.get(`${event}:${args[0]}:${args[1]}`);
                this.streamListeners.delete(`${event}:${args[0]}:${args[1]}`);
                return this.removeListener<any>(`${event}:${args[0]}:${args[1]}`, func);
            }
            case "verify": {
                if (!this.verifyListeners.has(`${event}:${args[0]}`)) {
                    throw new Error(`${event}:${args[0]} does not exist!`);
                }
                const func = this.verifyListeners.get(`${event}:${args[0]}`);
                this.verifyListeners.delete(`${event}:${args[0]}`);
                return this.removeListener<any>(`${event}:${args[0]}`, func);
            }
            default: {
                if (listener) {
                    return this.removeListener<E>(event, listener);
                }
            }
        }
    }
    emitter<E extends keyof InternalEventTypes>(event: E, emitArgs: string[], ...args: Arguments<InternalEventTypes[E]>): boolean {
        try {
            switch (event) {
                case "stream": {
                    this.emit<any>(`stream:${emitArgs[0]}:${emitArgs[1]}`, ...args);
                    break;
                }
                case "verify": {
                    this.emit<any>(`verify:${emitArgs[0]}`, ...args);
                    break;
                }
                default: {
                    this.emit<E>(event, ...args);
                }
            }
        } catch (e) {
            return false;
        }
        return true;
    }
}
export {
    TypedEvents,
    InternalEvents
}
