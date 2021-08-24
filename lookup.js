import { lookup } from 'dns'
import { promisify } from 'util'

// for whatever fucking reason, jest can't resolve imports from dns/promises (but not dns)
export default promisify(lookup)
