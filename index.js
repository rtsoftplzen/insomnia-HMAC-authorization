const crypto = require('crypto');

// konstanty klíčů

const PREFIX = 'HMAC-';

const ACCESS_KEY = PREFIX + 'accessKey';
const SIGNING_KEY = PREFIX + 'signingKey';

// konstanta signature metody

const SIGNATURE_METHOD_HMAC_SHA256 = 'HMAC-SHA256';

module.exports.requestHooks = [
  context => {
    let headers = context.request.getHeaders();

    let names = headers.map(header => header.name);

    if (names.includes(ACCESS_KEY) && names.includes(SIGNING_KEY)) {
      let accessKey, signingKey;

      headers.map(header => header.name === ACCESS_KEY ? accessKey = header.value : signingKey = header.value);

      const timestamp = Math.round(+new Date() / 1000);
      const signatureObject = {
        uri: context.request.getUrl().replace(/.*\/\/[^/]*/, ''),
        method: context.request.getMethod(),
        timestamp: timestamp,
        postBody: context.request.getBodyText(),
      };
      const signature = crypto
        .createHmac('SHA256', signingKey)
        .update(stringifyStable(signatureObject), 'utf8')
        .digest('base64');
      context.request.setHeader(
        'Authorization',
        SIGNATURE_METHOD_HMAC_SHA256 +
        ' Credential=' +
        accessKey +
        '/' +
        timestamp +
        ', Signature=' +
        signature,
      );

      // Odstranění přebytečných hlaviček

      context.request.removeHeader(ACCESS_KEY);
      context.request.removeHeader(SIGNING_KEY);
    }
  }
];

stringifyStable = function (obj, opts) {
  if (!opts) opts = {};
  if (typeof opts === 'function') opts = { cmp: opts };
  let space = opts.space || '';
  if (typeof space === 'number') space = Array(space + 1).join(' ');
  let cycles = typeof opts.cycles === 'boolean' ? opts.cycles : false;
  let replacer =
    opts.replacer ||
    function (key, value) {
      return value;
    };

  let cmp =
    opts.cmp &&
    (function (f) {
      return function (node) {
        return function (a, b) {
          let aobj = { key: a, value: node[a] };
          let bobj = { key: b, value: node[b] };
          return f(aobj, bobj);
        };
      };
    })(opts.cmp);

  let seen = [];
  return (function stringifyStable(parent, key, node, level) {
    let indent = space ? '\n' + new Array(level + 1).join(space) : '';
    let colonSeparator = space ? ': ' : ':';

    if (node && node.toJSON && typeof node.toJSON === 'function') {
      node = node.toJSON();
    }

    node = replacer.call(parent, key, node);

    if (node === undefined) {
      return;
    }
    if (typeof node !== 'object' || node === null) {
      return JSON.stringify(node);
    }
    if (Array.isArray(node)) {
      let out = [];
      for (let i = 0; i < node.length; i++) {
        let item = stringifyStable(node, i, node[i], level + 1) || JSON.stringify(null);
        out.push(indent + space + item);
      }
      return '[' + out.join(',') + indent + ']';
    } else {
      if (seen.indexOf(node) !== -1) {
        if (cycles) return JSON.stringify('__cycle__');
        throw new TypeError('Converting circular structure to JSON');
      } else seen.push(node);

      let keys = Object.keys(node).sort(cmp && cmp(node));
      let out = [];
      for (let i = 0; i < keys.length; i++) {
        let key = keys[i];
        let value = stringifyStable(node, key, node[key], level + 1);

        if (!value) continue;

        let keyValue = JSON.stringify(key) + colonSeparator + value;
        out.push(indent + space + keyValue);
      }
      seen.splice(seen.indexOf(node), 1);
      return '{' + out.join(',') + indent + '}';
    }
  })({ '': obj }, '', obj, 0);
};
