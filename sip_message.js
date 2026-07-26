import { Grammar } from './grammar.js';

/**
      SIP message  
      It's modified sip_message.js from JsSIP project.
      Copyright (c) 2012-2015 José Luis Millán - Versatica <https://github.com/versatica/>
      License: The MIT License
 */
class SipMessage {
    constructor() {
        this.method = null;
        this.cseq = null;
        this.ruri = null;          // request
        this.status_code = null;   // response
        this.reason_phrase = null; // response
        this.headers = {};
        this.body = null;
        this.raw = null;
    }

    isRequest() { return this.status_code === null; }
    isResponse() { return this.status_code !== null; }

    setRequest(method, uri) {
        this.method = method;
        this.ruri = uri;
        this.status_code = null;
        this.reason_phrase = null;
    }

    setResponse(status_code, reason_phrase) {
        this.status_code = status_code;
        this.reason_phrase = reason_phrase;
        this.ruri = null;
    }

    // Value must include header name, colon, value
    setHeaderValue(name, value) {
        this.headers[headerize(name)] = [value];
    }

    setHeader(name, value) {
        this.setHeaderValue(name, `${name}: ${value}`);
    }

    copyHeaders(message, name) {
        name = headerize(name);
        if (message.headers[name]) {
            this.headers[name] = structuredClone(message.headers[name]);
        }
    }

    addHeaderValue(name, value) {
        name = headerize(name);
        if (!this.headers[name])
            this.headers[name] = [];
        this.headers[name].push(value);
    }


    getHeader(name) {
        const header = this.headers[headerize(name)];
        return header ? header[0] : null;
    }

    getHeaderValue(name) {
        const header = this.headers[headerize(name)];
        if (!header)
            return null;
        const nameValue = header[0];
        let { value } = SipMessage.splitHeaderNameValue(nameValue);
        return value;
    }

    getParsedHeader(name) {
        let nameValue = this.getHeader(name);
        if (!nameValue)
            return null;
        let { value } = SipMessage.splitHeaderNameValue(nameValue);
        return SipMessage.parseHeader(name, value);
    }

    getHeaders(name) {
        const headers = this.headers[headerize(name)];
        return headers ? headers : [];
    }

    hasHeader(name) {
        return (this.headers[headerize(name)]) ? true : false;
    }

    setHeaders(name, headers) {
        this.headers[headerize(name)] = headers;
    }

    static splitHeaderNameValue(data, headerStart = 0, headerEnd = 0) {
        if (headerEnd === 0)
            headerEnd = data.length;

        const colonIndex = data.indexOf(':', headerStart);
        if (colonIndex === -1)
            throw new Error(`getHeaderNameValue() Missed colon. "${data.substring(headerStart, headerEnd)}"`);

        const name = data.substring(headerStart, colonIndex).trim();
        const value = data.substring(colonIndex + 1, headerEnd).trim();
        return { name, value };
    }

    /* 
      Parse header 
        return {name, value, parsed}
        parsed == null if it's unknown header.
        parsed can be Object or Array
    */
    static parseHeader(name, value) {
        let parsed;
        let multiple = false;
        // If header-field is well-known, parse it.
        switch (name.toLowerCase()) {
            case 'via':
            case 'v':
                parsed = Grammar.parse(value, 'Via');
                // Note: looks like defined grammar limitation. Not allowed multiple Via in the same line.
                break;
            case 'from':
            case 'f':
                parsed = Grammar.parse(value, 'From');
                break;
            case 'to':
            case 't':
                parsed = Grammar.parse(value, 'To');
                break;
            case 'record-route':
                parsed = Grammar.parse(value, 'Record_Route');
                multiple = true;
                break;
            case 'call-id':
            case 'i':
                parsed = Grammar.parse(value, 'Call_ID');
                break;
            case 'contact':
            case 'm':
                parsed = Grammar.parse(value, 'Contact');
                multiple = true;
                break;
            case 'content-length':
            case 'l':
                parsed = Grammar.parse(value, 'Content_Length');
                break;
            case 'content-type':
            case 'c':
                parsed = Grammar.parse(value, 'Content_Type');
                break;
            case 'cseq':
                parsed = Grammar.parse(value, 'CSeq');
                break;
            case 'max-forwards':
                parsed = Grammar.parse(value, 'Max_Forwards');
                break;
            case 'www-authenticate':
                parsed = Grammar.parse(value, 'WWW_Authenticate');
                break;
            case 'proxy-authenticate':
                parsed = Grammar.parse(value, 'Proxy_Authenticate');
                break;
            case 'authorization':
                parsed = Grammar.parse(value, 'Authorization');
                break;
            /*
            case 'proxy-authorization':
                parsed = Grammar.parse(value, 'Proxy_Authorization');
                break;
            */
            case 'session-expires':
            case 'x':
                parsed = Grammar.parse(value, 'Session_Expires');
                break;
            case 'refer-to':
            case 'r':
                parsed = Grammar.parse(value, 'Refer_To');
                break;
            case 'replaces':
                parsed = Grammar.parse(value, 'Replaces');
                break;
            case 'event':
            case 'o':
                parsed = Grammar.parse(value, 'Event');
                break;
            default:
                parsed = null;
        }
        if (parsed === -1)
            throw new Error(`Cannot parse header: ${value}`);

        if (parsed !== null) {
            if (multiple && !Array.isArray(parsed))
                throw new Error(`Header ${name} must be multiple`);
        }
        return parsed;
    }

    // Parse message constructor
    static parse(data) {
        let message = new SipMessage();
        let bodyStart;
        let headerEnd = data.indexOf('\r\n');

        if (headerEnd === -1)
            throw new Error('no CRLF found, not a SIP message');

        // Parse first line. Check if it is a Request or a Reply.
        const firstLine = data.substring(0, headerEnd);
        let parsed = Grammar.parse(firstLine, 'Request_Response');

        if (parsed === -1)
            throw new Error(`error parsing first line of SIP message: "${firstLine}"`);

        message = new SipMessage();
        if (!parsed.status_code) {
            message.setRequest(parsed.method, parsed.uri);
        } else {
            message.setResponse(parsed.status_code, parsed.reason_phrase);
        }

        message.raw = data;
        let headerStart = headerEnd + 2;

        // Read headers loop. 
        // Parse each header 
        for (; ;) {
            headerEnd = SipMessage.findHeaderEndIndex(data, headerStart);

            // The SIP message has normally finished.
            if (headerEnd === -2) {
                bodyStart = headerStart + 2;
                break;
            }

            // Data.indexOf returned -1 due to a malformed message.
            if (headerEnd === -1) {
                throw Error('malformed message');
            }

            let { name, value } = SipMessage.splitHeaderNameValue(data, headerStart, headerEnd);
            let nameValue = data.substring(headerStart, headerEnd).trim();
            message.addHeaderValue(name, nameValue);

            if (name.toLowerCase() === 'cseq') {
                let parsed = SipMessage.parseHeader(name, value);
                message.method = parsed.method;
                message.cseq = parsed.value;
            }

            headerStart = headerEnd + 2;
        }

        // Set body
        if (message.hasHeader('content-length')) {
            const contentLength = message.getParsedHeader('content-length');
            message.body = data.substring(bodyStart, bodyStart + contentLength);
        } else {
            message.body = data.substring(bodyStart);
        }
        if (message.body.length === 0)
            message.body = null;
        return message;
    }

    // Return index or -1 when error, -2 end of message
    static findHeaderEndIndex(data, headerStart) {
        // 'start' position of the header.
        let start = headerStart;
        // 'end' position of the header.
        let end = 0;
        // 'partial end' position of the header.
        let partialEnd = 0;

        // End of message.
        if (data.substring(start, start + 2).match(/(^\r\n)/)) {
            return -2;
        }

        while (end === 0) {
            // Partial End of Header.
            partialEnd = data.indexOf('\r\n', start);

            // 'indexOf' returns -1 if the value to be found never occurs.
            if (partialEnd === -1)
                return -1;

            if (!data.substring(partialEnd + 2, partialEnd + 4).match(/(^\r\n)/) && data.charAt(partialEnd + 2).match(/(^\s+)/)) {
                // Not the end of the message. Continue from the next position.
                start = partialEnd + 2;
            } else {
                end = partialEnd;
            }
        }
        return end;
    }


    toString() {
        if (!this.raw)
            this.build();
        return this.raw;
    }

    build() {
        if (this.ruri) {
            this.raw = `${this.method} ${this.ruri.toString()} SIP/2.0\r\n`;
        } else {
            this.raw = `SIP/2.0 ${this.status_code} ${this.reason_phrase}\r\n`;
        }
        for (let name of Object.keys(this.headers)) {
            for (let v of this.headers[name])
                this.raw += v + '\r\n';
        }
        this.raw += '\r\n';
        if (this.body)
            this.raw += this.body;
    }
}


function headerize(string) {
    const exceptions = {
        'Call-Id': 'Call-ID',
        'Cseq': 'CSeq',
        'Www-Authenticate': 'WWW-Authenticate'
    };

    const name = string.toLowerCase()
        .replace(/_/g, '-')
        .split('-');
    let hname = '';
    const parts = name.length;
    let part;

    for (part = 0; part < parts; part++) {
        if (part !== 0) {
            hname += '-';
        }
        hname += name[part].charAt(0).toUpperCase() + name[part].substring(1);
    }
    if (exceptions[hname]) {
        hname = exceptions[hname];
    }

    return hname;
}

function escapeUser(user) {
    return encodeURIComponent(decodeURIComponent(user))
        .replace(/%3A/ig, ':')
        .replace(/%2B/ig, '+')
        .replace(/%3F/ig, '?')
        .replace(/%2F/ig, '/');
}

class NameAddrHeader {
    static parse(name_addr_header) {
        name_addr_header = Grammar.parse(name_addr_header, 'Name_Addr_Header');

        if (name_addr_header !== -1) {
            return name_addr_header;
        } else {
            return undefined;
        }
    }

    constructor(uri, display_name, parameters) {
        if (!uri || !(uri instanceof URI)) {
            throw new TypeError('missing or invalid "uri" parameter');
        }

        this._uri = uri;
        this._parameters = {};
        this.display_name = display_name;

        for (const param in parameters) {
            if (Object.prototype.hasOwnProperty.call(parameters, param)) {
                this.setParam(param, parameters[param]);
            }
        }
    }

    get uri() {
        return this._uri;
    }

    get display_name() {
        return this._display_name;
    }

    set display_name(value) {
        this._display_name = (value === 0) ? '0' : value;
    }

    setParam(key, value) {
        this._parameters[key.toLowerCase()] = (typeof value === 'undefined' || value === null) ? null : value.toString();
    }

    getParam(key) {
        return this._parameters[key.toLowerCase()];
    }

    hasParam(key) {
        return (this._parameters.hasOwnProperty(key.toLowerCase()) && true) || false;
    }

    deleteParam(parameter) {
        parameter = parameter.toLowerCase();
        if (this._parameters.hasOwnProperty(parameter)) {
            const value = this._parameters[parameter];

            delete this._parameters[parameter];

            return value;
        }
    }

    clearParams() {
        this._parameters = {};
    }

    _quote(str) {
        return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    toString() {
        let body = this._display_name ? `"${this._quote(this._display_name)}" ` : '';

        body += `<${this._uri.toString()}>`;

        for (const parameter in this._parameters) {
            if (Object.prototype.hasOwnProperty.call(this._parameters, parameter)) {
                body += `;${parameter}`;

                if (this._parameters[parameter] !== null) {
                    body += `=${this._parameters[parameter]}`;
                }
            }
        }

        return body;
    }
}

class URI {
    static parse(uri) {
        uri = Grammar.parse(uri, 'SIP_URI');
        return uri !== -1 ? uri : undefined;
    }

    constructor(scheme, user, host, port, parameters = {}, headers = {}) {
        if (!host)
            throw new TypeError('missing or invalid "host" parameter');

        this._parameters = {};
        this._headers = {};

        this._scheme = scheme || JsSIP_C.SIP;
        this._user = user;
        this._host = host;
        this._port = port;

        for (let param in parameters) {
            this.setParam(param, parameters[param]);
        }

        for (let header in headers) {
            this.setHeader(header, headers[header]);
        }
    }

    get scheme() { return this._scheme; }
    set scheme(value) { this._scheme = value.toLowerCase(); }
    get user() { return this._user; }
    set user(value) { this._user = value; }
    get host() { return this._host; }
    set host(value) { this._host = value.toLowerCase(); }
    get port() { return this._port; }
    set port(value) { this._port = value === 0 ? value : (parseInt(value, 10) || null); }

    setParam(key, value) {
        this._parameters[key.toLowerCase()] = (typeof value === 'undefined' || value === null) ? null : value.toString();
    }

    getParam(key) {
        return this._parameters[key.toLowerCase()];
    }

    hasParam(key) {
        return (this._parameters.hasOwnProperty(key.toLowerCase()) && true) || false;
    }

    deleteParam(parameter) {
        parameter = parameter.toLowerCase();
        if (this._parameters.hasOwnProperty(parameter)) {
            const value = this._parameters[parameter];
            delete this._parameters[parameter];
            return value;
        }
    }

    clearParams() { this._parameters = {}; }

    setHeader(name, value) { this._headers[headerize(name)] = (Array.isArray(value)) ? value : [value]; }
    getHeader(name) { return this._headers[headerize(name)]; }
    hasHeader(name) { return (this._headers.hasOwnProperty(headerize(name)) && true) || false; }

    deleteHeader(header) {
        header = headerize(header);
        if (this._headers.hasOwnProperty(header)) {
            const value = this._headers[header];
            delete this._headers[header];
            return value;
        }
    }

    clearHeaders() { this._headers = {}; }

    toString() {
        const headers = [];
        let uri = `${this._scheme}:`;
        if (this._user)
            uri += `${escapeUser(this._user)}@`;
        uri += this._host;
        if (this._port)
            uri += `:${this._port}`;

        for (const parameter in this._parameters) {
            uri += `;${parameter}`;
            if (this._parameters[parameter] !== null) {
                uri += `=${this._parameters[parameter]}`;
            }
        }

        for (const header in this._headers) {
            for (const item of this._headers[header]) {
                headers.push(`${header}=${item}`);
            }
        }

        if (headers.length > 0)
            uri += `?${headers.join('&')}`;
        return uri;
    }

    toAor(show_port) {
        let aor = `${this._scheme}:`;
        if (this._user)
            aor += `${escapeUser(this._user)}@`;
        aor += this._host;
        if (show_port && this._port)
            aor += `:${this._port}`;
        return aor;
    }
};



export { SipMessage, NameAddrHeader, URI };
