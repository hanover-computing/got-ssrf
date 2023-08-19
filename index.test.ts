import { promisify } from 'util'
import nock from 'nock'
import CacheableLookup from 'cacheable-lookup'

// We can directly mock the "import { lookup } from 'dns'" call in index.js with vitest.
import * as mockDns from './__mocks__/dns.js'
vi.mock('dns', () => mockDns)

// However, it does mean that we need to do a dynamic import to make sure we load the mocked import.
// See: https://jestjs.io/docs/ecmascript-modules#module-mocking-in-esm
const { gotSsrf } = await import('./index.js')

nock.disableNetConnect()

// Whether you pass in dnsCache: true, or an *instance* of CacheableLookup,
// the dnsCache.lookupAsync being used is from an instance of the CacheableLookup class,
// so we don't have to separately test the { dnsCache: true } case.
// We just need to ensure that this library works correctly with a dnsCache.lookupAsync.
const dnsCache = new CacheableLookup()

// Also, for some reason trying to pass a mocked resolver with a resolve4() and a resolve6()
// that always throws ENOTFOUND doesn't work (i.e. it doesn't use the `lookup` we pass to the options).
// So we just directly mock lookupAsync.
vi.spyOn(dnsCache, 'lookupAsync').mockImplementation(
  promisify(mockDns.lookup) as CacheableLookup['lookupAsync']
)

const setups = [
  {
    title: 'dnsCache',
    options: {
      dnsCache
    }
  },
  {
    title: 'dnsLookup',
    options: {
      dnsLookup: mockDns.lookup as unknown as CacheableLookup['lookup']
    }
  },
  {
    title: 'native dns',
    options: {}
  }
]

describe('got-ssrf', () => {
  describe.each(setups)('w/ $title', ({ options }) => {
    const got = gotSsrf.extend(options)

    it('rejects non-http(s) protocols', async () => {
      await expect(got('ftp://example.com')).rejects.toThrow(
        'Unsupported protocol: ftp'
      )

      await expect(got('http2://example.com')).rejects.toThrow(
        'Unsupported protocol: http2'
      )

      await expect(got('file:///etc/passwd')).rejects.toThrow(
        'Unsupported protocol: file'
      )

      // You *need* to specify the protocol
      await expect(got('example.com')).rejects.toThrow('Invalid URL')
    })

    it('works for public address', async () => {
      nock('http://public-url.com').get('/').reply(200)
      await got('http://public-url.com/')
    })

    it('throws for reserved addresses', async () => {
      nock('http://private-url.com').get('/').reply(200)
      await expect(got('http://private-url.com/')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )
    })

    it('checks every redirect', async () => {
      // Basically, we prevent "smuggling" internal endpoints from a public hostname
      // by checking the URL before every redirect.
      // In this example, the seemingly public URL redirects to private-url.com,
      // so even though the private-url.com ultimately redirects the URL to a public one,
      // we must still reject this request!
      nock(
        'http://public-url-that-redirects-to-private-url-that-redirects-to-public-url.com'
      )
        .get('/')
        .reply(301, 'Moved', { Location: 'http://private-url.com/' })
      nock('http://private-url.com')
        .get('/')
        .reply(301, 'Moved', { Location: 'http://public-url.com/' })
      nock('http://public-url.com').get('/').reply(200)
      await expect(
        got(
          'http://public-url-that-redirects-to-private-url-that-redirects-to-public-url.com'
        )
      ).rejects.toThrow('The IP of the domain is reserved!')
    })

    it('handles weird URLs/edge cases', async () => {
      await expect(got('http://public-url.com.')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )

      await expect(got('http://example.com:foo')).rejects.toThrow('Invalid URL')

      // Below are trick cases from https://azeemba.com/posts/what-is-a-url.html#query-or-username

      // Based on the http://http://http://@http://http://?http://#http:// example.
      await expect(
        got('http://private://part2://@part3://part4://?part5://#part6://')
      ).rejects.toThrow('The IP of the domain is reserved!')

      // Query or Username?
      await expect(got('http://1.1.1.1 &@ 2.2.2.2# @3.3.3.3/')).rejects.toThrow(
        'Invalid URL'
      )

      await expect(got('http://1.1.1.1&@127.0.0.1#@3.3.3.3/')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )

      // Port or Path?
      await expect(got('http://127.0.0.1:5000:80/')).rejects.toThrow(
        'Invalid URL'
      )

      // Host confusion (see: https://daniel.haxx.se/blog/2021/04/19/curl-those-funny-ipv4-addresses/)
      await expect(got('http://127.0.1')).rejects.toThrow(
        'The IP of the domain is reserved!' // the first number assumed to be 8 bits, the next 8, then 16
      )
      await expect(got('http://127.1')).rejects.toThrow(
        'The IP of the domain is reserved!' // the first number assumed to be 8 bits, the next one 24
      )
      await expect(got('http://2130706433')).rejects.toThrow(
        'The IP of the domain is reserved!' // 32-bit number converted as IPv4 addresses
      )
      await expect(got('http://0300.0250.0.01')).rejects.toThrow(
        'The IP of the domain is reserved!' // zero-prefix = octal number -> converted to 192.168.0.1
      )
      await expect(got('http://0xc0.0xa8.0x00.0x01')).rejects.toThrow(
        'The IP of the domain is reserved!' // same deal, but octal
      )

      // Other weird hostnames
      await expect(got('http://example.com%2F10.0.0.1/')).rejects.toThrow(
        'Invalid URL'
      )
    })

    // NOTE: for IP address tests, any valid IP address will be processed directly in the code,
    // without the need for a DNS lookup (after all, you do a DNS lookup to get the IP address).
    // Therefore, we do not need DNS mocks (__mocks__/dns.js) for the tests below.

    it('handles IPv4 addresses', async () => {
      // A private IPv4 address
      await expect(got('http://192.168.0.1')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )

      // Commonly used for metadata services in cloud environments
      await expect(got('http://169.254.169.254')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )

      // A public IPv4 address
      nock('http://1.1.1.1').get('/').reply(200)
      await got('http://1.1.1.1')
    })

    it('handles IPv6 addresses', async () => {
      // This is 127.0.0.1 mapped to IPv6
      await expect(got('http://[::ffff:7f00:1]:1338/hello')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )

      // A public IPv4 address (1.1.1.1) mapped to IPv6
      nock('http://[::ffff:101:101]').get('/').reply(200)
      await got('http://[::ffff:101:101]')

      // A public IPv6 address
      nock('http://[2606:2800:220:1:248:1893:25c8:1946]').get('/').reply(200)
      await got('http://[2606:2800:220:1:248:1893:25c8:1946]')

      // A private IPv6 address
      await expect(got('http://[::1]')).rejects.toThrow(
        'The IP of the domain is reserved!'
      )
    })

    it('handles hostnames with brackets in it', async () => {
      await expect(got('http://[hostname1.com')).rejects.toThrow('Invalid URL')

      await expect(got('http://[hostnam]e2.com')).rejects.toThrow('Invalid URL')

      await expect(
        got('http://[2606:2800:220:1:248:1893:25c8:g]')
      ).rejects.toThrow('Invalid URL')
    })
  })
})
