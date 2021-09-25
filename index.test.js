import { expect, describe, it } from '@jest/globals'
import nock from 'nock'
import { gotSsrf } from './index.js'

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
})
