import { lookup as nativeCallbackLookup } from 'dns'
import { promisify } from 'util'
import got, { Options } from 'got'
import ip from 'ipaddr.js'
import debugGen from 'debug'

import type CacheableLookup from 'cacheable-lookup'

const debug = debugGen('got-ssrf')
const nativeLookup = promisify(nativeCallbackLookup) // importing straight from dns/promises limits node.js version to 15 or higher

type LookupFn = (hostname: string) => Promise<{ address: string }>

// The caller's own DNS settings, saved on the pinned lookup so that later hops (redirects) can
// still use them for their check.
const ORIGINAL = Symbol('got-ssrf original dns settings')
type Original = Pick<Options, 'dnsCache' | 'dnsLookup'>
type Pinned = NonNullable<Options['dnsLookup']> & { [ORIGINAL]?: Original }

// Assume all URLs are properly formed by the time it hits the hooks
const protect = async (options: Options) => {
  // On a redirect, options.dnsLookup is the pinned lookup from the previous hop, so use the
  // caller's original settings for this hop's check.
  const previous = options.dnsLookup as Pinned | undefined
  const original: Original = previous?.[ORIGINAL] ?? {
    dnsCache: options.dnsCache,
    dnsLookup: options.dnsLookup
  }

  let lookup: LookupFn
  if (original.dnsCache) {
    debug('Using user-provided dnsCache.lookupAsync')
    lookup = (original.dnsCache as CacheableLookup).lookupAsync
  } else if (original.dnsLookup) {
    debug('Promisifying user-provided dnsLookup')
    lookup = promisify(
      original.dnsLookup
    ) as unknown as CacheableLookup['lookupAsync'] // yay wildly incorrect types
  } else {
    debug('Falling back to native dns/promises lookup')
    lookup = nativeLookup
  }

  // To prevent Server Side Request Forgery, we need to check the protocol.
  // Otherwise, you could end up making requests to internal services (e.g. the database)
  // that are within the same network but is not intended to be reached by the user.
  // This is done automatically by got, so we don't need to do anything here:
  // https://github.com/sindresorhus/got/blob/8f77e8d07d8684cde95d351feafaa308b466dff4/source/core/options.ts#L1411

  // Check if the hostname is an IP address - we don't need to "lookup" IP addresses!
  let IP: string

  // Even the got author himself casts this incorrect type: https://github.com/sindresorhus/got/blob/b1d61c173a681755ac23afb2f155f08801c1e7e4/source/core/index.ts#L1121
  const { hostname } = options.url as URL

  if (ip.IPv4.isIPv4(hostname)) {
    IP = hostname
  } else if (
    // Per https://url.spec.whatwg.org/#host-parsing,
    // if the hostname starts with a [, we need to check if it ends with a ], and is an IPv6.
    hostname.startsWith('[') &&
    hostname.endsWith(']') &&
    ip.IPv6.isIPv6(hostname.slice(1, -1)) // strip the first and last characters - the brackets
  ) {
    IP = hostname.slice(1, -1)
  } else {
    // A regular hostname - we need to do a DNS lookup to get the IP address
    const { address } = await lookup(hostname)
    IP = address
  }

  // Another layer of protection against SSRF - ensure we're not hitting internal services.
  // Try to match "reserved" IP ranges: https://en.wikipedia.org/wiki/Reserved_IP_addresses
  // https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#case-2-application-can-send-requests-to-any-external-ip-address-or-domain-name
  // The function returns 'unicast' or the name of the reserved IP range, should it match any.
  // This in effect blocks all private IP Range: https://git.io/JWy3u, https://git.io/JWy3b
  // We use ip.process() here to deal with potentially IPv4-mapped IPv6 addresses (which will show up as "ipv4mapped"
  // and not the whatever range the actual IPv4 address actually belongs to).
  if (ip.process(IP).range() !== 'unicast')
    throw new Error('The IP of the domain is reserved!')

  // Pin the connection to the address we just checked. Without this, got resolves the hostname
  // again when it connects, so a DNS answer that changed (rebinding), or a later record in a
  // multi-record answer, could send the request to an address that was never checked.
  // The DNS cache is turned off for the connection as well, so it cannot answer with a different address.
  const pinned = pinnedLookup(IP) as unknown as Pinned
  pinned[ORIGINAL] = original
  options.dnsLookup = pinned
  options.dnsCache = false
}

// A lookup function that always returns the given address, and honours both the callback form
// and the { all: true } form that Node uses for happy-eyeballs connections.
const pinnedLookup = (address: string) => {
  const family = ip.IPv6.isIPv6(address) ? 6 : 4
  return (
    _hostname: string,
    optionsOrCallback: unknown,
    maybeCallback?: unknown
  ) => {
    const callback = (
      typeof optionsOrCallback === 'function'
        ? optionsOrCallback
        : maybeCallback
    ) as (err: null, address: unknown, family?: number) => void
    const wantsAll =
      typeof optionsOrCallback === 'object' &&
      optionsOrCallback !== null &&
      (optionsOrCallback as { all?: boolean }).all === true
    if (wantsAll) callback(null, [{ address, family }])
    else callback(null, address, family)
  }
}

export const gotSsrf = got.extend({
  hooks: {
    beforeRequest: [protect],
    beforeRedirect: [protect]
  }
})
