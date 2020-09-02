import * as express from 'express'
import * as path from 'path';
import * as cookieParser from 'cookie-parser';
import * as logger from 'morgan';
import * as sassMiddleware from 'node-sass-middleware';
import * as cors from 'cors';
import * as useragent from 'express-useragent';
import * as http from 'http';
import * as process from 'process';
import {FindPeers} from "../find-peers";
export class MonitorServer {
    public app: express.Application;
    private server: any;
    private findPeerAccessor: FindPeers;
    private port = 3000;
    constructor(findPeer: FindPeers, port: number) {
        this.findPeerAccessor = findPeer;
        this.app = express();
        this.app.use(useragent.express());
        this.app.use(cors());
        this.app.use(logger('dev'));
        this.app.use(express.json({limit: '100mb'}));
        this.app.use(express.urlencoded({limit: '100mb', extended: true}));
        this.app.use(cookieParser());
        this.app.use(sassMiddleware({
            src: path.join(__dirname, 'public'),
            dest: path.join(__dirname, 'public'),
            indentedSyntax: true,
            sourceMap: true
        }));
        this.port = port;
        this.app.set('port', this.port);
    }
    init() {
        this.app.use(express.static(path.join(__dirname, 'public')));
        this.server = http.createServer(this.app);
        this.app.get('/clients', (req, res) => {
            res.write(JSON.stringify(Array.from(this.findPeerAccessor.getClients().entries()), null, 4));
            res.status(200).end();
        });
        this.server.listen(this.port);
        this.server.on('error', (error) => {
            if (error.syscall !== 'listen') {
                throw error;
            }
            const bind = typeof this.port === 'string'
                ? 'Pipe ' + this.port
                : 'Port ' + this.port;

            // handle specific listen errors with friendly messages
            switch (error.code) {
                case 'EACCES':
                    console.error(bind + ' requires elevated privileges');
                    process.exit(1);
                    break;
                case 'EADDRINUSE':
                    console.error(bind + ' is already in use');
                    process.exit(1);
                    break;
                default:
                    throw error;
            }
        });
        this.server.on('listening', () => {
            const addr = this.server.address();
            const bind = typeof addr === 'string'
                ? 'pipe ' + addr
                : 'port ' + addr.port;
            console.log('Listening on ' + bind);
        });
    }
}
