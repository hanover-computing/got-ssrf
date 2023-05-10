import { expect, describe, it, jest } from '@jest/globals'
import nock from 'nock'

// We can directly mock the "import { lookup } from 'dns'" call in index.js with jest.
const mockDnsModule = await import('./__mocks__/dns.js')
jest.unstable_mockModule('dns', () => mockDnsModule)

// However, it does mean that we need to do a dynamic import to make sure we load the mocked import.
// See: https://jestjs.io/docs/ecmascript-modules#module-mocking-in-esm
const { gotSsrf } = await import('./index.js')

nock.disableNetConnect()

describe('got-ssrf', () => {
  it('works for public address', async () => {
    nock('http://public-url.com').get('/').reply(200)
    await gotSsrf('http://public-url.com/')
  })

  it('throws for reserved addresses', async () => {
    nock('http://private-url.com').get('/').reply(200)
    await expect(gotSsrf('http://private-url.com/')).rejects.toThrow(
      'The IP of the domain is reserved!'
    )
  })

  it('checks every redirect', async () => {
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
      gotSsrf(
        'http://public-url-that-redirects-to-private-url-that-redirects-to-public-url.com'
      )
    ).rejects.toThrow('The IP of the domain is reserved!')
  })

  // NOTE: for IP address tests, any valid IP address will be processed directly in the code,
  // without the need for a DNS lookup (after all, you do a DNS lookup to get the IP address).
  // Therefore, we do not need DNS mocks (__mocks__/dns.js) for the tests below.

  it('handles IPv4 addresses', async () => {
    // A private IPv4 address
    await expect(gotSsrf('http://192.168.0.1')).rejects.toThrow(
      'The IP of the domain is reserved!'
    )

    // A public IPv4 address
    nock('http://1.1.1.1').get('/').reply(200)
    await gotSsrf('http://1.1.1.1')
  })

  it('handles IPv6 addresses', async () => {
    // This is 127.0.0.1 mapped to IPv6
    await expect(gotSsrf('http://[::ffff:7f00:1]:1338/hello')).rejects.toThrow(
      'The IP of the domain is reserved!'
    )

    // A public IPv4 address (1.1.1.1) mapped to IPv6
    nock('http://[::ffff:101:101]').get('/').reply(200)
    await gotSsrf('http://[::ffff:101:101]')

    // A public IPv6 address
    nock('http://[2606:2800:220:1:248:1893:25c8:1946]').get('/').reply(200)
    await gotSsrf('http://[2606:2800:220:1:248:1893:25c8:1946]')

    // A private IPv6 address
    await expect(gotSsrf('http://[fe80::ffff:ffff:ffff:ffff]')).rejects.toThrow(
      'The IP of the domain is reserved!'
    )
  })

  it('handles hostnames with brackets in it', async () => {
    await expect(gotSsrf('http://[hostname1.com')).rejects.toThrow(
      'Invalid URL'
    )

    await expect(gotSsrf('http://[hostnam]e2.com')).rejects.toThrow(
      'Invalid URL'
    )

    await expect(
      gotSsrf('http://[2606:2800:220:1:248:1893:25c8:g]')
    ).rejects.toThrow('Invalid URL')
  })
})
