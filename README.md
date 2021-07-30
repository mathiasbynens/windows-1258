# windows-1258 [![Build status](https://github.com/mathiasbynens/windows-1258/workflows/run-checks/badge.svg)](https://github.com/mathiasbynens/windows-1258/actions?query=workflow%3Arun-checks) [![windows-1258 on npm](https://img.shields.io/npm/v/windows-1258)](https://www.npmjs.com/package/windows-1258)

_windows-1258_ is a robust JavaScript implementation of [the windows-1258 character encoding as defined by the Encoding Standard](https://encoding.spec.whatwg.org/#windows-1258).

This encoding is known under the following names: cp1258, windows-1258, and x-cp1258.

## Installation

Via [npm](https://www.npmjs.com/):

```bash
npm install windows-1258
```

In a browser:

```html
<script src="windows-1258.js"></script>
```

In [Node.js](https://nodejs.org/):

```js
const windows1258 = require('windows-1258');
```

## API

### `windows1258.version`

A string representing the semantic version number.

### `windows1258.labels`

An array of strings, each representing a [label](https://encoding.spec.whatwg.org/#label) for this encoding.

### `windows1258.encode(input, options)`

This function takes a plain text string (the `input` parameter) and encodes it according to windows-1258. The return value is a ‘byte string’, i.e. a string of which each item represents an octet as per windows-1258.

```js
const encodedData = windows1258.encode(text);
```

The optional `options` object and its `mode` property can be used to set the [error mode](https://encoding.spec.whatwg.org/#error-mode). For encoding, the error mode can be `'fatal'` (the default) or `'html'`.

```js
const encodedData = windows1258.encode(text, {
  mode: 'html'
});
// If `text` contains a symbol that cannot be represented in windows-1258,
// instead of throwing an error, it will return an HTML entity for the symbol.
```

### `windows1258.decode(input, options)`

This function takes a byte string (the `input` parameter) and decodes it according to windows-1258.

```js
const text = windows1258.decode(encodedData);
```

The optional `options` object and its `mode` property can be used to set the [error mode](https://encoding.spec.whatwg.org/#error-mode). For decoding, the error mode can be `'replacement'` (the default) or `'fatal'`.

```js
const text = windows1258.decode(encodedData, {
  mode: 'fatal'
});
// If `encodedData` contains an invalid byte for the windows-1258 encoding,
// instead of replacing it with U+FFFD in the output, an error is thrown.
```

For decoding a buffer (e.g. from `fs.readFile`) use `buffer.toString('binary')` to get the byte string which `decode` takes.

## Notes

[Similar modules for other single-byte legacy encodings are available.](https://www.npmjs.com/browse/keyword/legacy-encoding)

## Author

| [![twitter/mathias](https://gravatar.com/avatar/24e08a9ea84deb17ae121074d0f17125?s=70)](https://twitter.com/mathias "Follow @mathias on Twitter") |
|---|
| [Mathias Bynens](https://mathiasbynens.be/) |

## License

_windows-1258_ is available under the [MIT](https://mths.be/mit) license.
