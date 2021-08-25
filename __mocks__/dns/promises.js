// get http://localhost to resolve to something for testing purposes!
export async function lookup(hostname) {
  return hostname === 'http://localhost'
    ? { address: '127.0.0.1', family: 4 }
    : { address: '1.1.1.1', family: 4 }
}
