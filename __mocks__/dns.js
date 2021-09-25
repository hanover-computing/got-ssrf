// A fucking workaround because jest can't fucking mock builtin modules in ESM mode mother fuck

export function lookup(hostname, options, callback) {
  if (callback === undefined) {
    callback = options
  }

  if (hostname === 'public-url.com') {
    // The callback return format has to be in form of object as util.promisify doesn't know
    // that it's supposed to translate callback(error, address, family) into return value of {address, family}
    callback(undefined, { address: '1.1.1.1', family: 4 }) // something I know is public
  }

  if (hostname === 'private-url.com') {
    callback(undefined, { address: '192.168.0.1', family: 4 }) // should be caught by SSRF protection
  }

  if (
    hostname ===
    'public-url-that-redirects-to-private-url-that-redirects-to-public-url.com'
  ) {
    callback(undefined, { address: '1.1.1.1', family: 4 })
  }
}
