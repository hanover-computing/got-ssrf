// temporary workaround while we wait for https://github.com/facebook/jest/issues/9771
const resolver = require('enhanced-resolve').create.sync({
  conditionNames: ['require', 'node', 'default'],
  extensions: ['.js', '.json', '.node', '.ts', '.tsx']
})

module.exports = function (request, options) {
  // This is an EXTREMELY hacky workaround for jest not being able to load manual mocks for ES Modules.
  // Man, fuck this shit.
  if (request.includes('dns')) request = request.replace('dns', '__mocks__/dns')

  // list global module that must be resolved by defaultResolver here
  if (
    ['util', 'url', 'tls', 'http', 'https', 'stream', 'events', 'net'].includes(
      request
    )
  ) {
    return options.defaultResolver(request, options)
  }

  return resolver(options.basedir, request)
}
