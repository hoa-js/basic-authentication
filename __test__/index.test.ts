import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import { basicAuth } from '../src/index'
import { tinyRouter } from '@hoajs/tiny-router'

async function defaultHashFunction (data: string | object | boolean) {
  let sourceBuffer: ArrayBuffer | ArrayBufferView
  if (ArrayBuffer.isView(data) || data instanceof ArrayBuffer) {
    sourceBuffer = data
  } else {
    sourceBuffer = new TextEncoder().encode(typeof data === 'object' ? JSON.stringify(data) : String(data))
  }
  const buffer = await crypto.subtle.digest({
    name: 'SHA-256'
  }, sourceBuffer as BufferSource)
  const hash = Array.prototype.map.call(new Uint8Array(buffer), (x: number) => x.toString(16).padStart(2, '0')).join('')
  return hash
}

describe('basicAuthd middleware', () => {
  let handlerExecuted: boolean

  beforeEach(() => {
    handlerExecuted = false
  })

  const app = new Hoa()
  app.extend(tinyRouter())
  const username = 'hoa-user-a'
  const password = 'hoa-password-a'
  const unicodePassword = '炎'

  const usernameB = 'hoa-user-b'
  const passwordB = 'hoa-password-b'

  const usernameC = 'hoa-user-c'
  const passwordC = 'hoa-password-c'

  app.get(
    '/auth/*',
    basicAuth({
      username,
      password,
    })
  )
  // Test multiple handlers
  app.get('/auth/*', async (ctx, next) => {
    ctx.res.set('x-custom', 'foo')
    await next()
  })

  app.get(
    '/auth-unicode/*',
    basicAuth({
      username,
      password: unicodePassword,
    })
  )

  app.get(
    '/invalid-base64/*',
    basicAuth({
      username: usernameB,
      password: passwordB,
    })
  )

  app.get(
    '/auth-multi/*',
    basicAuth(
      {
        username: usernameB,
        password: passwordB,
      },
      {
        username: usernameC,
        password: passwordC,
      }
    )
  )

  app.get(
    '/auth-override-func/*',
    basicAuth({
      username,
      password,
      hashFunction: defaultHashFunction,
    })
  )

  app.get(
    '/error-custom-hash-function',
    basicAuth({
      username,
      password,
      hashFunction: (() => false) as any,
    })
  )

  app.get('/nested/*', async (c, next) => {
    const auth = basicAuth({ username, password })
    return auth(c, next)
  })

  app.get('/verify-user/*', basicAuth({
    verifyUser: (ctx, username, password) => {
      return (
        ctx.req.pathname === '/verify-user' &&
        username === 'dynamic-user' &&
        password === 'hoa-password'
      )
    },
  }))

  app.get(
    '/auth-custom-invalid-user-message-string/*',
    basicAuth({
      username,
      password,
      invalidUserMessage: 'Custom unauthorized message as string',
    })
  )

  app.get(
    '/auth-custom-invalid-user-message-function-string/*',
    basicAuth({
      username,
      password,
      invalidUserMessage: () => 'Custom unauthorized message as function string',
    })
  )

  app.get('/auth/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })
  app.get('/auth-unicode/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })
  app.get('/auth-multi/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })
  app.get('/auth-override-func/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })

  app.get('/nested/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'nested'
  })

  app.get('/verify-user', async (ctx, next) => {
    handlerExecuted = true
    ctx.res.body = 'verify-user'
    await next()
  })

  app.get('/auth-custom-invalid-user-message-string/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })

  app.get('/auth-custom-invalid-user-message-function-string/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })

  it('Should authorize', async () => {
    const credential = btoa(username + ':' + password)

    const req = new Request('http://localhost/auth/a')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(res).not.toBeNull()
    expect(handlerExecuted).toBeTruthy()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('auth')
    expect(res.headers.get('x-custom')).toBe('foo')
  })

  it('Should not authorize', async () => {
    const req = new Request('http://localhost/auth/a')
    const res = await app.fetch(req)
    expect(res).not.toBeNull()
    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('x-custom')).toBeNull()
  })

  it('Should authorize Unicode', async () => {
    const credential = btoa(username + ':' + unescape(encodeURIComponent(unicodePassword)))

    const req = new Request('http://localhost/auth-unicode/a')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(handlerExecuted).toBeTruthy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('auth')
  })

  it('Should authorize multiple users', async () => {
    let credential = btoa(usernameB + ':' + passwordB)

    let req = new Request('http://localhost/auth-multi/b')
    req.headers.set('Authorization', `Basic ${credential}`)
    let res = await app.fetch(req)
    expect(handlerExecuted).toBeTruthy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('auth')

    handlerExecuted = false
    credential = btoa(usernameC + ':' + passwordC)
    req = new Request('http://localhost/auth-multi/c')
    req.headers.set('Authorization', `Basic ${credential}`)
    res = await app.fetch(req)
    expect(handlerExecuted).toBeTruthy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('auth')
  })

  it('Should authorize with sha256 function override', async () => {
    const credential = btoa(username + ':' + password)

    const req = new Request('http://localhost/auth-override-func/a')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(handlerExecuted).toBeTruthy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('auth')
  })

  it('Should authorize - nested', async () => {
    const credential = btoa(username + ':' + password)

    const req = new Request('http://localhost/nested')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(handlerExecuted).toBeTruthy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('nested')
  })

  it('Should not authorize - nested', async () => {
    const credential = btoa('foo' + ':' + 'bar')

    const req = new Request('http://localhost/nested')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(handlerExecuted).toBeFalsy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
  })

  it('Should authorize - verifyUser', async () => {
    const credential = btoa('dynamic-user' + ':' + 'hoa-password')

    const req = new Request('http://localhost/verify-user')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(handlerExecuted).toBeTruthy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('verify-user')
  })

  it('Should not authorize - verifyUser', async () => {
    const credential = btoa('foo' + ':' + 'bar')

    const req = new Request('http://localhost/verify-user')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)
    expect(handlerExecuted).toBeFalsy()
    expect(res).not.toBeNull()
    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
  })

  it('Should not authorize - custom invalid user message as string', async () => {
    const req = new Request('http://localhost/auth-custom-invalid-user-message-string')
    const res = await app.fetch(req)
    expect(res).not.toBeNull()
    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
    expect(res.headers.get('WWW-Authenticate')).toMatch(/Custom unauthorized message as string/)
    expect(await res.text()).toBe('Unauthorized')
  })

  it('Should not authorize - custom invalid user message as function string', async () => {
    const req = new Request('http://localhost/auth-custom-invalid-user-message-function-string')
    const res = await app.fetch(req)
    expect(res).not.toBeNull()
    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
    expect(res.headers.get('WWW-Authenticate')).toMatch(/Custom unauthorized message as function string/)
    expect(await res.text()).toBe('Unauthorized')
  })

  it('Should not authorize - invalid config', async () => {
    expect(() => app.get(
      '/error-config',
      basicAuth({ username } as any)
    )).toThrow(/Basic Auth middleware requires options for "username and password" or "verifyUser"/)
  })

  it('should not authorize - custom hash function return falsy', async () => {
    const credential = btoa('foo' + ':' + 'bar')

    const req = new Request('http://localhost/error-custom-hash-function')
    req.headers.set('Authorization', `Basic ${credential}`)

    const res = await app.fetch(req)
    expect(res.status).toBe(401)
  })

  it('should handle invalid base64 in Authorization header', async () => {
    const req = new Request('http://localhost/invalid-base64')
    req.headers.set('Authorization', 'Basic ////')

    const res = await app.fetch(req)
    expect(res.status).toBe(401)
  })
})
