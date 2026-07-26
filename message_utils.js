import { SipMessage } from './sip_message.js';
import { log } from './main.js';
import { createHash, randomBytes } from 'crypto';

function createResponse(request, statusCode, reasonPhrase, headers = [], body = null) {
    if (!request.isRequest())
        throw new Error('not request');
    let response = new SipMessage();
    response.setResponse(statusCode, reasonPhrase);
    response.method = request.method;
    response.copyHeaders(request, 'Via');
    response.copyHeaders(request, 'From');
    let requestTo = request.getHeader('To');
    let responseTo = requestTo;
    if (!requestTo.toLowerCase().includes('tag=')) {
        responseTo += `;tag=${createToken(10)}`;
    }
    response.setHeaderValue('To', responseTo);
    response.copyHeaders(request, 'Call-ID');
    response.copyHeaders(request, 'CSeq');
    for (let header of headers) {
        const colonIndex = header.indexOf(':');
        if (colonIndex === -1)
            throw new Error(`createResponse() Missed colon. "${header}"`);
        const name = header.substring(0, colonIndex).trim();
        response.addHeaderValue(name, header);
    }
    if (body) {
        response.body = body;
        response.setHeader('Content-Length', `${body.length}`);
    } else {
        response.setHeader('Content-Length', '0');
    }
    return response;
}

function create401Response(request, nonce) {
    let realm = 'DefaultSipRealm';
    let auth = `WWW-Authenticate: Digest realm="${realm}",nonce="${nonce}",qop="auth",algorithm=MD5`;
    let response = createNonOKResponse(request, 401, 'Unauthorized', [auth]);
    return response;
}

function createOKResponse(request) {
    if (!request.isRequest())
        throw new Error('not request');
    let response = createResponse(request, 200, 'OK');
    if (request.hasHeader('Contact')) response.copyHeaders(request, 'Contact');
    if (request.hasHeader('Allow')) response.copyHeaders(request, 'Allow');
    if (request.hasHeader('Expires')) response.copyHeaders(request, 'Expires');
    if (request.hasHeader('Server')) response.copyHeaders(request, 'Server');
    return response;
}

function createNonOKResponse(request, statusCode, reasonPhrase, headers = [], body = null) {
    if (!request.isRequest())
        throw new Error('not request');
    return createResponse(request, statusCode, reasonPhrase, headers, body);
}

function createToken(size) {
    return randomBytes(Math.ceil(size / 2)).toString('hex').substring(0, size);
}

function computeOngoingVia(request) {
    const callID = request.getParsedHeader('Call-ID');
    const toTag = request.getParsedHeader('To')?._parameters?.tag ?? '';
    const fromTag = request.getParsedHeader('From')?._parameters?.tag ?? '';
    const cseq = String(request.cseq);
    const requestURL = request.ruri.toString();
    const topMostBranch = request.getParsedHeader('Via').branch;
    const components = [callID, toTag, fromTag, cseq, requestURL, topMostBranch].map(val => val || "").join("|");
    const truncHash = createHash('sha256').update(components).digest('hex').substring(0, 16);
    const branch = `z9hG4bK${truncHash}`;
    return `Via: SIP/2.0/WSS proxy.invalid;branch=${branch}`;
}

function createOutgoingMessage(message) {
    if (message.isRequest()) {
        let maxForwards = message.getHeaderValue('Max-Forwards');
        if (maxForwards !== null) {
            maxForwards = parseInt(maxForwards);
            if (isNaN(maxForwards) || maxForwards <= 0) {
                throw new Error('Max-Forwards is zero');
            }
            message.setHeader('Max-Forwards', (maxForwards - 1).toString());
        }
    }
    if (message.isResponse()) {
        // Remove topmost Via
        let vias = message.getHeaders('Via');
        vias.shift();
        message.setHeaders('Via', vias);
    } else {
        // Add topmost Via
        let vias = message.getHeaders('Via');
        let via = computeOngoingVia(message);
        vias.unshift(via);
        message.setHeaders('Via', vias);
    }
    // Force rebuild
    message.raw = null;
    return message;
}

function getRegisterExpires(message) {
    let expires = -1; // means no expires header found
    let strExpires = null;
    try {
        let contact = message.getParsedHeader('Contact');
        if (contact && contact.length > 0 && contact[0].parsed && contact[0].parsed._parameters
            && contact[0].parsed._parameters['expires'] !== undefined) {
            strExpires = contact[0].parsed._parameters['expires'];
            expires = parseInt(strExpires);
        } else if (message.hasHeader('Expires')) {
            strExpires = message.getHeaderValue('Expires');
            expires = parseInt(strExpires);
        }
    } catch (e) {
        log.error(`getRegisterExpires() exception: ${e.message}`);
        return -2; // means error parsing expires header
    }
    return expires;
}

function hasToTag(message) {
    const toTag = message.getParsedHeader('To')?._parameters?.tag ?? '';
    return toTag !== '';
}

function getCallLeg(message, forceEarly = false) {
    const callID = message.getParsedHeader('Call-ID');
    const fromTag = message.getParsedHeader('From')?._parameters?.tag ?? '';
    const toTag = message.getParsedHeader('To')?._parameters?.tag ?? '';
    if (forceEarly || toTag === '') {
        return `${callID}|${fromTag}|#early`;
    }
    return fromTag > toTag ? `${callID}|${fromTag}|${toTag}` : `${callID}|${toTag}|${fromTag}`;
}


export {
    createResponse, create401Response, createOKResponse, createNonOKResponse, createToken,
    createOutgoingMessage, getRegisterExpires, hasToTag, getCallLeg
};
