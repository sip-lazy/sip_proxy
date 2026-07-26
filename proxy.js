import { log, logReg, credentials } from './main.js';
import { SipMessage } from './sip_message.js';
import { create401Response, createOKResponse, createNonOKResponse, createToken, 
    createOutgoingMessage, getRegisterExpires, hasToTag, getCallLeg } from './message_utils.js';
import { parseAuthorization, calculateResponse } from './digest_authentication.js';

let connections = new Map(); // connection-id -> ws
let calls = new Map();       // call leg      -> { callerWs, calleeWs, early, cleanupScheduled }

let connectionNumber = 0;

function conInfo(ws){
    if (!ws) return 'ws==null';
    return ws.info.user ? `${ws.info.id}:${ws.info.user}`: `${ws.info.id}`;
}

function wsConnectionHandler(ws, request) {
    let ip = request.socket.remoteAddress;
    if (ip.startsWith('::ffff:'))
        ip = ip.substring(7);

    connectionNumber++;
    ws.info = {
        id: `con-${connectionNumber}`,
        ip: ip,
        registered: false,
        nonce: '',
        user: '',
    };

    connections.set(ws.info.id, ws);
    log.info(`${conInfo(ws)} websocket open ip=${ws.info.ip}`);

    ws.on('close', () => {
        log.info(`${conInfo(ws)} websocket close`);
        for (let [callLeg, call] of calls.entries()) {
            if (call.callerWs === ws || call.calleeWs === ws) {
                log.info(`Cleaning up Call-ID: ${callLeg} due to socket closure`);
                calls.delete(callLeg);
            }
        }
        connections.delete(ws.info.id);
    });

    ws.on('message', (data) => {
        onMessage(ws, data);
    });
}

function onMessage(ws, data) {
    if (Buffer.isBuffer(data))
        data = data.toString();

    if (data === '\r\n\r\n') {
        log.trace(`${conInfo(ws)} websocket ping`);
        ws.send('\r\n');
        return;
    }

    let message;
    try {
        message = SipMessage.parse(data);
    } catch (e) {
        log.error(`${conInfo(ws)} Parsing exception`, e);
        return;
    }


    if (message.isRequest() && message.method === 'REGISTER') {
        incomingREGISTER(ws, message);
    } else {
        proxy(ws, message);
    }
}


function incomingREGISTER(ws, message) {
    let parsedTo = message.getParsedHeader('To');
    let user = parsedTo.uri.user;
    ws.info.user = user;

    if (!message.hasHeader('Authorization')) {
        logReg.debug(`${conInfo(ws)} REGISTER without Authorization`);
        ws.info.nonce = createToken(30);
        let responseMsg = create401Response(message, ws.info.nonce);
        let response401 = responseMsg.toString();
        logReg.debug(`${conInfo(ws)} Send response 401`);
        ws.send(Buffer.from(response401));
        return;
    }

    logReg.debug(`${conInfo(ws)} REGISTER with Authorization`);
    let auth = message.getHeader('Authorization');
    let map = parseAuthorization(auth);

    if (map.nonce !== ws.info.nonce) {
        logReg.debug(`${conInfo(ws)} Stale or invalid nonce. Send response 401.`);
        ws.info.nonce = createToken(30);
        let responseMsg = create401Response(message, ws.info.nonce);
        ws.send(Buffer.from(responseMsg.toString()));
        return;
    }

    let password = credentials[map.username];
    if (!password) {
        logReg.error(`${conInfo(ws)} Proxy don't know the user: ${map.username}`);
        ws.info.nonce = createToken(30);
        let responseMsg = create401Response(message, ws.info.nonce);
        let response401 = responseMsg.toString();
        logReg.debug(`${conInfo(ws)} Send response 401`);
        ws.send(Buffer.from(response401));
        return;
    }

    let correctResponse = calculateResponse({ method: 'REGISTER', map }, { username: map.username, password });

    if (map.response !== correctResponse) {
        logReg.error(`${conInfo(ws)} Wrong response ${map.response} Correct response ${correctResponse}`);
        ws.info.nonce = createToken(30);
        let responseMsg = create401Response(message, ws.info.nonce);
        let response401 = responseMsg.toString();
        logReg.debug(`${conInfo(ws)} Send response 401`);
        ws.send(Buffer.from(response401));
        return;
    }

    let response200 = createOKResponse(message);
    ws.send(Buffer.from(response200.toString()));

    for (let existingWs of connections.values()) {
        if (existingWs !== ws && existingWs.info.registered && existingWs.info.user === user) {
            if (isConnectionInActiveCall(existingWs)) {
                logReg.info(`${conInfo(existingWs)} ${user} has active call, only unregistered. New registration: ${conInfo(ws)}`);
                existingWs.info.registered = false;
            } else {
                logReg.info(`${conInfo(existingWs)} ${user} closed due to new registration from ${conInfo(ws)}`);
                existingWs.info.registered = false;
                existingWs.close(1000, 'Replaced by new registration');
            }
        }
    }
    
    let expires = getRegisterExpires(message);
    if (expires > 0) {
        ws.info.registered = true;
    } else {
        ws.info.registered = false;
    }
    logReg.debug(`${conInfo(ws)} Send response 200`);
    logReg.info(`${conInfo(ws)} ${ws.info.registered ? 'Registered' : 'Unregistered'} user ${ws.info.user}`);
}


function isConnectionInActiveCall(ws) {
    for (let call of calls.values()) {
        if (call.callerWs === ws || call.calleeWs === ws)
            return true;
    }
    return false;
}


function findConnectionWithRegisteredUser(user) {
    for (let ws of connections.values()) {
        if (ws.info.registered && ws.info.user === user)
            return ws;
    }
    return null;
}


function messageToString(message) {
    return message.isRequest() ? `${message.method}` : `${message.status_code} ${message.method}`;
}

function proxy(ws, message) {
    // Try to find an existing call tracking this Call-Leg
    let callleg = getCallLeg(message);
    let call = calls.get(callleg);

    if( !call && message.isResponse() && message.method === 'INVITE' && hasToTag(message)) {
        let earlyCallLeg = getCallLeg(message, true);
        call = calls.get(earlyCallLeg);
        if( call ) {
            log.debug(`${conInfo(ws)} Added final call-leg ${callleg}`);
            calls.set(callleg, call);
        }
    }

    if( call && call.early && message.isResponse() && message.method === 'INVITE' && message.status_code >= 200 && message.status_code < 300) {
        call.early = false;
        let earlyCallLeg = getCallLeg(message, true);
        log.debug(`${conInfo(ws)} Removed early call-leg ${earlyCallLeg}`);
        calls.delete(earlyCallLeg);
    }

    // CANCEL requests have no To-tag (RFC 3261 §9.1), so they still use the early callleg key
    // even after a 180 Ringing promoted the stored entry to the final callleg.
    if (!call && message.isRequest() && message.method === 'CANCEL') {
        let earlyCallLeg = getCallLeg(message, true);
        call = calls.get(earlyCallLeg);
        if (call) {
            log.info(`${conInfo(ws)} CANCEL matched early call-leg ${earlyCallLeg}`);
            callleg = earlyCallLeg;
        }
    }

    // If no call exists and it's a new INVITE, build the link profile
    if (!call) {
        if (message.isRequest() && message.method === 'INVITE') {
            let parsedTo = message.getParsedHeader('To');
            let user = parsedTo.uri.user;
            log.info(`${conInfo(ws)} Received initial INVITE for user: \"${user}\"`);

            let calleeWs = findConnectionWithRegisteredUser(user);
            if (calleeWs === null) {
                let responseMsg = createNonOKResponse(message, 404, 'Not Found');
                log.info(`${conInfo(ws)} User: \"${user}\" not found. Send response 404`);
                ws.send(Buffer.from(responseMsg.toString()));
                return;
            }

            // Create call object mapping this specific call string
            call = { callerWs: ws, calleeWs: calleeWs, early: true, cleanupScheduled: false };
            calls.set(callleg, call);
            log.info(`${conInfo(ws)} Created early call-leg ${callleg} mapped: ${conInfo(call.callerWs)} <--> ${conInfo(call.calleeWs)}`);
        } else {
            // It's a non-INVITE request or response for a call we don't know about
            if (message.isRequest()) {
                if (message.method !== 'ACK') {
                    log.debug(`${conInfo(ws)} Send 404 to ${message.method} request`);
                    let responseMsg = createNonOKResponse(message, 404, 'Not Found');
                    ws.send(Buffer.from(responseMsg.toString()));
                }
            }
            return;
        }
    }

    // Determine who the target recipient socket is for this packet
    let targetWs = (ws === call.callerWs) ? call.calleeWs : call.callerWs;

    // Verify the destination socket is healthy and alive
    if (targetWs && targetWs.readyState !== 1) {
        log.error(`${conInfo(ws)} Target connection ${conInfo(targetWs)} for call-Leg ${callleg} is not ready`);
        calls.delete(callleg);
        return;
    }

    // Forward the message to the companion socket
    if (targetWs) {
        log.info(`${conInfo(ws)} forwarding ${messageToString(message)} to ${conInfo(targetWs)}`);

        let outgoingMessage;
        try {
            outgoingMessage = createOutgoingMessage(message);
        } catch (e) {
            log.error(`${conInfo(ws)} Error creating outgoing message for Call-Leg ${callleg}: ${e.message}`);
            if (e.message === 'Max-Forwards is zero') {
                let responseMsg = createNonOKResponse(message, 483, 'Too Many Hops');
                log.info(`${conInfo(ws)} send 483 to ${message.method} request due to Max-Forwards=0`);
                ws.send(Buffer.from(responseMsg.toString())); 
            } 
            return;
        }
        targetWs.send(Buffer.from(outgoingMessage.toString()));

        // Clean up state only after the BYE transaction completes (any final response)
        if (message.isResponse() && message.method === 'BYE' && message.status_code >= 200) {
            log.info(`${conInfo(ws)} Call-Leg: ${callleg} terminated via BYE ${message.status_code}.`);
            calls.delete(callleg);
        }

        // Clean up state if an early INVITE is rejected (includes 487 triggered by CANCEL).
        // Do NOT clean up for re-INVITE rejections (RFC 3261 §14) — the session continues.
        if (message.isResponse() && message.method === 'INVITE' && message.status_code >= 400 && call.early) {
            log.info(`${conInfo(ws)} Call-Leg: ${callleg} will be cleared due to INVITE response: ${message.status_code}`);
            if (!call.cleanupScheduled) {
                call.cleanupScheduled = true;
                const earlyLeg = getCallLeg(message, true);
                setTimeout(() => {
                    log.info(`Call-Leg: ${callleg} removed due to INVITE response ${message.status_code} after 32 second timeout.`);
                    calls.delete(callleg);
                    calls.delete(earlyLeg);
                }, 32000);
            }
        }

    }
}

// The Global Garbage Sweep Loop
// Runs continuously every 60 seconds in the background
setInterval(() => {
    log.trace("Executing proxy active call validation sweep...");

    for (let [callLeg, call] of calls.entries()) {
        const isCallerDead = !call.callerWs || call.callerWs.readyState !== 1;
        const isCalleeDead = !call.calleeWs || call.calleeWs.readyState !== 1;

        if (isCallerDead || isCalleeDead) {
            log.warn(`Sweep caught dead websocket channel for Call-Leg: ${callLeg}. Evicting map entry.`);
            try {
                if (!isCallerDead) call.callerWs.close(4000, "Call leg broken");
                if (!isCalleeDead) call.calleeWs.close(4000, "Call leg broken");
            } catch (err) {
                log.error(`Failed pushing closing notifications for Call-Leg ${callLeg}`, err);
            }
            calls.delete(callLeg);
        }
    }
}, 60000); // 1 minute

export { wsConnectionHandler };