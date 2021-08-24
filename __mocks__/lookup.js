// get http://localhost to resolve to something for testing purposes!
export default function (hostname) {
  return hostname === 'http://localhost'
    ? { address: '127.0.0.1', family: 4 }
    : { address: '1.1.1.1', family: 4 }
}
