import { gotSsrf } from './index.js'

describe('got-ssrf', () => {
  test('works for public address', async () => {
    await gotSsrf('http://google.com')
  })

  test('throws for reserved addresses', async () => {
    await expect(gotSsrf('http://localhost')).rejects.toThrow(
      'The IP of the domain is reserved!'
    )
  })
})
