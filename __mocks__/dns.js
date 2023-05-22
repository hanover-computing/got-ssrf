// We use the hostname lookups to define how got should behave when visiting a URL.
// For URLs that are supposed to be public, we return a public IP address.
// For URLs that are supposed to be private, we return a private IP address.
// This, *in conjunction with* the HTTP request mocking (the `nock` module),
// defines the entire behaviour of what a request looks like.
export function lookup(hostname, options, callback) {
  if (callback === undefined) {
    callback = options
  }

  if (hostname === 'public-url.com') {
    // The callback return format has to be in form of object as util.promisify doesn't know
    // that it's supposed to translate callback(error, address, family) into return value of {address, family}
    callback(undefined, { address: '1.1.1.1', family: 4 }) // something I know is public
  }

  if (
    hostname === 'private-url.com' ||
    hostname === 'public-url.com.' ||
    hostname === 'private'
  ) {
    callback(undefined, { address: '192.168.0.1', family: 4 }) // should be caught by SSRF protection
  }

  if (
    hostname ===
    'public-url-that-redirects-to-private-url-that-redirects-to-public-url.com'
  ) {
    callback(undefined, { address: '1.1.1.1', family: 4 })
  }

  // Really make sure that all test cases - at least, the ones that resolve an actual hostname -
  // have a corresponding DNS mock as well (on top of the HTTP mock).
  callback(new Error('DNS lookup was not mocked'))
}
