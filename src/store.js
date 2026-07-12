'use strict';

const fs = require('node:fs');
const path = require('node:path');

class JsonStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.queue = Promise.resolve();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    if (!fs.existsSync(filePath)) {
      this._writeSync({
        schema: 1,
        products: [],
        licenses: [],
        activations: [],
        audit: []
      });
    }
  }

  _readSync() {
    const raw = fs.readFileSync(this.filePath, 'utf8');
    const data = JSON.parse(raw);
    data.products ??= [];
    data.licenses ??= [];
    data.activations ??= [];
    data.audit ??= [];
    return data;
  }

  _writeSync(data) {
    const temp = `${this.filePath}.tmp`;
    fs.writeFileSync(temp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, this.filePath);
  }

  read() {
    return this._readSync();
  }

  mutate(mutator) {
    const operation = this.queue.then(async () => {
      const data = this._readSync();
      const result = await mutator(data);
      if (data.audit.length > 1000) data.audit = data.audit.slice(-1000);
      this._writeSync(data);
      return result;
    });
    this.queue = operation.catch(() => {});
    return operation;
  }
}

module.exports = { JsonStore };
