import got from 'got'
import ip from 'ipaddr.js'
import { lookup as nativeLookup } from 'dns/promises'
import debugGen from 'debug'
import { promisify } from 'util'

const debug = debugGen('got-ssrf')

const ALLOWED_PROTOCOLS = ['http:', 'https:']

export const gotSsrf = got.extend({
  hooks: {
    beforeRequest: [
      // Assume all URLs are properly formed at this point
      async options => {
        // To prevent Server Side Request Forgery, we need to check the protocol.
        // Otherwise, you could end up making requests to internal services (e.g. the database)
        // that are within the same network but is not intended to be reached by the user.
        if (!ALLOWED_PROTOCOLS.includes(options.url.protocol))
          throw new Error('Invalid protocol!')

        let lookup = nativeLookup

        if (options.dnsCache) {
          debug('Using user-provided dnsCache.lookupAsync')
          lookup = options.dnsCache.lookupAsync
        } else if (options.dnsLookup) {
          debug('Promisifying user-provided dnsLookup')
          lookup = promisify(options.dnsLookup)
        } else {
          debug('Falling back to native dns/promises lookup')
        }

        // Another layer of protection against SSRF - ensure we're not hitting internal services
        const { address } = await lookup(options.url.hostname)
        // Try to match "reserved" IP ranges: https://en.wikipedia.org/wiki/Reserved_IP_addresses
        // https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#case-2-application-can-send-requests-to-any-external-ip-address-or-domain-name
        // The function returns 'unicast' or the name of the reserved IP range, should it match any.
        // This in effect blocks all private IP Range: https://git.io/JWy3u, https://git.io/JWy3b
        if (ip.parse(address).range() !== 'unicast')
          throw new Error('The IP of the domain is reserved!')
      }
    ]
  }
})
