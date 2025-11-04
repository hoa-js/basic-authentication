import type { HoaContext, HoaMiddleware } from 'hoa'

type MessageFunction = (c: HoaContext) => string | Promise<string>
type HashFunction = (data: string | object | boolean) => string | Promise<string>

type BasicAuthOptions =
  | {
    username: string
    password: string
    realm?: string
    hashFunction?: HashFunction
    invalidUserMessage?: string | MessageFunction
  }
  | {
    verifyUser: (c: HoaContext, username: string, password: string) => boolean | Promise<boolean>
    realm?: string
    hashFunction?: HashFunction
    invalidUserMessage?: string | MessageFunction
  }

/**
 * Basic Authentication middleware for Hoa.
 *
 * @param {BasicAuthOptions} options - The options for basic authentication middleware.
 * @param {string} options.username - The username for authentication.
 * @param {string} options.password - The password for authentication.
 * @param {string} [options.realm=ctx.app.name] - The realm attribute for the WWW-Authenticate header.
 * @param {HashFunction} [options.hashFunction] - The hash function used for secure comparison.
 * @param {Function} [options.verifyUser] - The function to verify user credentials.
 * @param {string | MessageFunction} [options.invalidUserMessage="Unauthorized"] - The invalid user message.
 * @returns {HoaMiddleware} The middleware handler function
 * @throws {HttpError} 401 Unauthorized when basic authentication fails
 */
export function basicAuth (options: BasicAuthOptions, ...users: { username: string; password: string }[]): HoaMiddleware {
  const usernamePasswordInOptions = 'username' in options && 'password' in options
  const verifyUserInOptions = 'verifyUser' in options

  if (!(usernamePasswordInOptions || verifyUserInOptions)) {
    throw new Error(
      'Basic Auth middleware requires options for "username and password" or "verifyUser"'
    )
  }
  const { hashFunction = defaultHashFunction, invalidUserMessage = 'Unauthorized' } = options
  if (usernamePasswordInOptions) {
    users.unshift({ username: options.username, password: options.password })
  }

  return async function basicAuthMiddleware (ctx: HoaContext, next) {
    const realm = options.realm ?? ctx.app.name
    const requestUser = auth(ctx)
    if (requestUser) {
      if (verifyUserInOptions) {
        if (await options.verifyUser(ctx, requestUser.username, requestUser.password)) {
          await next()
          return
        }
      } else {
        for (const user of users) {
          const [usernameEqual, passwordEqual] = await Promise.all([
            timingSafeEqual(user.username, requestUser.username, hashFunction),
            timingSafeEqual(user.password, requestUser.password, hashFunction),
          ])
          if (usernameEqual && passwordEqual) {
            await next()
            return
          }
        }
      }
    }
    const responseMessage = typeof invalidUserMessage === 'function'
      ? await invalidUserMessage(ctx)
      : invalidUserMessage
    ctx.throw(401, responseMessage, {
      headers: {
        // RFC 7617 Basic Authentication
        'WWW-Authenticate': `Basic realm="${realm.replace(/"/g, '\\"')}"`
      }
    })
  }
}

const CREDENTIALS_REGEXP = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/
const USER_PASS_REGEXP = /^([^:]*):(.*)$/
const utf8Decoder = new TextDecoder()

function decodeBase64 (str: string): Uint8Array {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function auth (ctx: HoaContext): { username: string; password: string } | undefined {
  const match = CREDENTIALS_REGEXP.exec(ctx.req.get('Authorization') || '')
  if (!match) {
    return undefined
  }

  let userPass
  // If an invalid string is passed to atob(), it throws a `DOMException`.
  try {
    userPass = USER_PASS_REGEXP.exec(utf8Decoder.decode(decodeBase64(match[1])))
  } catch { } // Do nothing

  if (!userPass) {
    return undefined
  }

  return { username: userPass[1], password: userPass[2] }
}

async function timingSafeEqual (
  a: string | object | boolean,
  b: string | object | boolean,
  hashFunction?: HashFunction
): Promise<boolean> {
  const [sa, sb] = await Promise.all([hashFunction(a), hashFunction(b)])

  if (!sa || !sb) {
    return false
  }

  return sa === sb
}

async function defaultHashFunction (data: string | object | boolean): Promise<string> {
  const sourceBuffer = new TextEncoder().encode(JSON.stringify(data))
  const buffer = await crypto.subtle.digest({
    name: 'SHA-256'
  }, sourceBuffer as BufferSource)
  const hash = Array.prototype.map.call(new Uint8Array(buffer), (x: number) => x.toString(16).padStart(2, '0')).join('')
  return hash
}

export default basicAuth
