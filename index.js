import got from 'got'
import ip from 'ipaddr.js'
import lookup from './lookup.js'

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

        // Unfortunately, we can't use the dnsLookup/dnsCache that the user passed into got's options,
        // as got does not expose the damn thing.
        // As I really *really* don't want to recreate lookup/dnscache when the user might've already
        // specified dnsLookup or dnsCache (or rely on the default),
        // I am giving up and using the native dns lookup, instead of user-provided dnslookup/cache.
        // This means no caching, no lookup logic, etc.
        // Man, this really fucking sucks. However, there does seem to be a way to get around the issue of
        // DNS caching (natively): https://stackoverflow.com/questions/11020027/dns-caching-in-linux

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
