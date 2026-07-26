class ConsoleLogger {
    static LEVELS = { trace: 1, debug: 2, info: 3, warn: 4, error: 5 };

    constructor({ level = 'info', name = '' } = {}) {
        this.name = name;
        this.setLevel(level);
    }

    setLevel(level) {
        level = level.toLowerCase();
        let priority = ConsoleLogger.LEVELS[level];
        if (priority === undefined)
            throw new Error(`Wrong level name: "${level}"`);
        this.level = level;
        this.priority = priority;
    }

    trace(msg, val) { this._log('trace', msg, val); }
    debug(msg, val) { this._log('debug', msg, val); }
    info(msg, val) { this._log('info', msg, val); }
    warn(msg, val) { this._log('warn', msg, val); }
    error(msg, val) { this._log('error', msg, val); }

    _log(levelName, msg, val) {
        if (ConsoleLogger.LEVELS[levelName] < this.priority)
            return;
        let prefix = `[${levelName.toUpperCase()}] `;
        if (this.name) prefix += `${this.name} `;

        if (val !== undefined) {
            console.log(`${prefix}${msg}`, val);
        } else {
            console.log(`${prefix}${msg}`);
        }
    }
}

export { ConsoleLogger }