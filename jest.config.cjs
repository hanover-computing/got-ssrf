process.env.JEST_JUNIT_OUTPUT_DIR = 'reports/jest'

module.exports = {
  reporters: ['default', 'jest-junit'],
  errorOnDeprecated: true,
  notify: true
}
