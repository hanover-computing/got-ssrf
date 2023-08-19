import type { LookupOneOptions } from 'dns'

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  // In the real dns module, the callback signature is (err, address, family).
  // However, because this needs to get promisify'd (just like the real dns.lookup),
  // I'm choosing to return an object so the promisify'd function returns the object.
  result?: { address: string; family: number }
) => void

// We use the hostname lookups to define how got should behave when visiting a URL.
// For URLs that are supposed to be public, we return a public IP address.
// For URLs that are supposed to be private, we return a private IP address.
// This, *in conjunction with* the HTTP request mocking (the `nock` module),
// defines the entire behaviour of what a request looks like.
export function lookup(
  hostname: string,
  options: LookupOneOptions | LookupCallback,
  callback?: LookupCallback
) {
  if (callback === undefined) {
    callback = options as LookupCallback
  }

  if (hostname === 'public-url.com') {
    // The callback return format has to be in form of object as util.promisify doesn't know
    // that it's supposed to translate callback(error, address, family) into return value of {address, family}
    callback(null, { address: '1.1.1.1', family: 4 }) // something I know is public
  }

  if (
    hostname === 'private-url.com' ||
    hostname === 'public-url.com.' ||
    hostname === 'private'
  ) {
    callback(null, { address: '192.168.0.1', family: 4 }) // should be caught by SSRF protection
  }

  if (
    hostname ===
    'public-url-that-redirects-to-private-url-that-redirects-to-public-url.com'
  ) {
    callback(null, { address: '1.1.1.1', family: 4 })
  }

  // Really make sure that all test cases - at least, the ones that resolve an actual hostname -
  // have a corresponding DNS mock as well (on top of the HTTP mock).
  callback(new Error('DNS lookup was not mocked'))
}
