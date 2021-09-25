import { lookup as nativeCallbackLookup } from './dns.js' // HACK WARNING
import { promisify } from 'util'
import got from 'got'
import ip from 'ipaddr.js'
import debugGen from 'debug'

const debug = debugGen('got-ssrf')
const nativeLookup = promisify(nativeCallbackLookup) // importing straight from dns/promises limits node.js version to 15 or higher

const ALLOWED_PROTOCOLS = ['http:', 'https:']

// Assume all URLs are properly formed by the time it hits the hooks
const protect = async options => {
  let lookup
  if (options.dnsCache) {
    debug('Using user-provided dnsCache.lookupAsync')
    lookup = options.dnsCache.lookupAsync
  } else if (options.dnsLookup) {
    debug('Promisifying user-provided dnsLookup')
    lookup = promisify(options.dnsLookup)
  } else {
    debug('Falling back to native dns/promises lookup')
    lookup = nativeLookup
  }

  // To prevent Server Side Request Forgery, we need to check the protocol.
  // Otherwise, you could end up making requests to internal services (e.g. the database)
  // that are within the same network but is not intended to be reached by the user.
  if (!ALLOWED_PROTOCOLS.includes(options.url.protocol))
    throw new Error('Invalid protocol!')

  // Another layer of protection against SSRF - ensure we're not hitting internal services
  const { address } = await lookup(options.url.hostname)
  // Try to match "reserved" IP ranges: https://en.wikipedia.org/wiki/Reserved_IP_addresses
  // https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#case-2-application-can-send-requests-to-any-external-ip-address-or-domain-name
  // The function returns 'unicast' or the name of the reserved IP range, should it match any.
  // This in effect blocks all private IP Range: https://git.io/JWy3u, https://git.io/JWy3b
  if (ip.parse(address).range() !== 'unicast')
    throw new Error('The IP of the domain is reserved!')
}

export const gotSsrf = got.extend({
  hooks: {
    beforeRequest: [protect],
    beforeRedirect: [protect]
  }
})
