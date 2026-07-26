/**
 * Websocket SIP proxy 
 *
 * MIT License
 * Copyright (C) 2026 SIP Lazy
 */
import dotenv from 'dotenv';
import http from 'http';
import https from 'https';
import fs from 'fs';
import { WebSocketServer } from 'ws';
import { ConsoleLogger } from './console_logger.js';
import { wsConnectionHandler } from './proxy.js';
const SERVER_VERSION = '1.0.0';
let log, logReg;
let credentials = {};

main();

function main() {
    dotenv.config();

    log = new ConsoleLogger();
    logReg = new ConsoleLogger({ name: 'REG' })

    log.info(`**** SIP Proxy ${SERVER_VERSION} ****`);

    log.setLevel(getEnv('LOG_MAIN', 'info'));
    logReg.setLevel(getEnv('LOG_REG', 'info'));
    log.info(`Log level: main=${log.level} reg=${logReg.level}`);

    catchSignals();

    // Unhandled exceptions in libraries. Don't exit. Logs and continue.
    process.on('unhandledRejection', (reason, p) => {
        log.error(`Unhandled Rejection at: ${p}, reason: ${reason}`);
    });

    process.on('uncaughtException', (error) => {
        log.error(`Uncaught exception: ${error}\n` + `Exception origin: ${error.stack}`);
    });

    // User names and passwords.
    // 
    // USERS=name1 password1, name2 password2
    // USERS2=name3 password3, name4 password4
    for (let i = 1; ; i++) {
        let val = process.env[`USERS${i==1 ? '' : i.toString()}`];
        if (!val)
            break;
        let entries = val.split(',');
        for (let entry of entries) {
            entry = entry.trim();
            let spaceIndex = entry.indexOf(' ');
            if (spaceIndex === -1)
                continue;
            let user = entry.substring(0, spaceIndex).trim();
            let pass = entry.substring(spaceIndex + 1).trim();
            credentials[user] = pass;
        }
    }

    log.debug('credentials', JSON.stringify(credentials));

    try {
        let httpServer;
        try {
            httpServer = startServer();
        } catch (e) {
            log.error('Cannot start HTTP server');
            throw e;
        }

        httpServer.on('error', (err) => {
            log.error(`http server error: "${err.message}"`);
            exit(1);
        });

    } catch (e) {
        log.error(e);
        exit(1);
    }
}

function startServer() {
    let isHTTPS = (getEnv('HTTPS', 'true') === 'true');
    let port = parseInt(getEnv('PORT', '443'));

    let httpServer;

    if (isHTTPS) {
        let tlsCrt = fs.readFileSync(getEnv('TLS_CERTIFICATE'), 'utf8');
        let tlsKey = fs.readFileSync(getEnv('TLS_PRIVATE_KEY'), 'utf8');
        let options = { cert: tlsCrt, key: tlsKey };
        httpServer = https.createServer(options, httpHandler);
    } else {
        httpServer = http.createServer(httpHandler);
    }

    log.info(`${isHTTPS ? 'https' : 'http'} server`);
    let wsServer = new WebSocketServer({ server: httpServer });
    wsServer.on('connection', wsConnectionHandler);

    httpServer.listen(port);

    return httpServer;
}

function catchSignals() {
    process.once('SIGINT', closeGracefully);
    process.once('SIGTERM', closeGracefully);
}


function closeGracefully(signal) {
    log.error(`Received signal to terminate: ${signal}`);
    exit(1);
}

function exit(code, timeout = 500) {
    log.error(`terminating process with code: ${code}`);
    setTimeout(() => {
        process.exit(code);
    }, timeout);
}

function getEnv(name, defaultValue = undefined) {
    const v = process.env[name] ?? defaultValue;
    if (v === undefined)
        throw new Error(`Missed environment variable: ${name}`);
    return v.trim();
}

function httpHandler(request, response) {
    let ip = request.socket.remoteAddress;
    if (ip.startsWith('::ffff:'))
        ip = ip.substring(7);

    // Docker healthcheck
    if (ip === '127.0.0.1' || ip === '::1') {
        response.writeHead(200);
        response.end();
        return;
    }
    log.warn(`Ignored HTTP ${request.method} request`);
    response.writeHead(405);
    response.end();
}

export { log, logReg, credentials };
