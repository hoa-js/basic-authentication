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
    '/auth-custom-message/*',
    basicAuth({
      username,
      password,
      invalidUserMessage: (ctx) => `Custom message for ${ctx.req.pathname}`,
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

  app.get('/verify-user', async (ctx, next) => {
    handlerExecuted = true
    ctx.res.body = 'verify-user'
    await next()
  })

  app.get('/auth-custom-message/*', (ctx) => {
    handlerExecuted = true
    ctx.res.body = 'auth'
  })

  it('should authorize with correct credentials', async () => {
    const credential = btoa(username + ':' + password)
    const req = new Request('http://localhost/auth/a')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)

    expect(res.status).toBe(200)
    expect(handlerExecuted).toBeTruthy()
    expect(await res.text()).toBe('auth')
    expect(res.headers.get('x-custom')).toBe('foo')
  })

  it('should not authorize without credentials or with wrong credentials', async () => {
    // No credentials
    let req = new Request('http://localhost/auth/a')
    let res = await app.fetch(req)
    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('x-custom')).toBeNull()

    // Wrong credentials
    handlerExecuted = false
    const wrongCredential = btoa('wrong:credentials')
    req = new Request('http://localhost/auth/a')
    req.headers.set('Authorization', `Basic ${wrongCredential}`)
    res = await app.fetch(req)
    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
  })

  it('should authorize with Unicode password', async () => {
    const credential = btoa(username + ':' + unescape(encodeURIComponent(unicodePassword)))
    const req = new Request('http://localhost/auth-unicode/a')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)

    expect(res.status).toBe(200)
    expect(handlerExecuted).toBeTruthy()
    expect(await res.text()).toBe('auth')
  })

  it('should authorize multiple users', async () => {
    // First user
    let credential = btoa(usernameB + ':' + passwordB)
    let req = new Request('http://localhost/auth-multi/b')
    req.headers.set('Authorization', `Basic ${credential}`)
    let res = await app.fetch(req)
    expect(res.status).toBe(200)
    expect(handlerExecuted).toBeTruthy()

    // Second user
    handlerExecuted = false
    credential = btoa(usernameC + ':' + passwordC)
    req = new Request('http://localhost/auth-multi/c')
    req.headers.set('Authorization', `Basic ${credential}`)
    res = await app.fetch(req)
    expect(res.status).toBe(200)
    expect(handlerExecuted).toBeTruthy()
  })

  it('should authorize with custom hash function', async () => {
    const credential = btoa(username + ':' + password)
    const req = new Request('http://localhost/auth-override-func/a')
    req.headers.set('Authorization', `Basic ${credential}`)
    const res = await app.fetch(req)

    expect(res.status).toBe(200)
    expect(handlerExecuted).toBeTruthy()
  })

  it('should support custom verifyUser function', async () => {
    // Correct credentials
    let credential = btoa('dynamic-user' + ':' + 'hoa-password')
    let req = new Request('http://localhost/verify-user')
    req.headers.set('Authorization', `Basic ${credential}`)
    let res = await app.fetch(req)
    expect(res.status).toBe(200)
    expect(handlerExecuted).toBeTruthy()
    expect(await res.text()).toBe('verify-user')

    // Wrong credentials
    handlerExecuted = false
    credential = btoa('foo' + ':' + 'bar')
    req = new Request('http://localhost/verify-user')
    req.headers.set('Authorization', `Basic ${credential}`)
    res = await app.fetch(req)
    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
  })

  it('should support custom invalid user message function', async () => {
    const req = new Request('http://localhost/auth-custom-message/test')
    const res = await app.fetch(req)

    expect(res.status).toBe(401)
    expect(handlerExecuted).toBeFalsy()
    expect(res.headers.get('WWW-Authenticate')).toMatch('Basic realm="Hoa"')
    expect(await res.text()).toBe('Custom message for /auth-custom-message/test')
  })

  it('should throw error with invalid config', async () => {
    expect(() => basicAuth({ username } as any))
      .toThrow(/Basic Auth middleware requires options for "username and password" or "verifyUser"/)
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

  it('should handle realm configuration correctly', async () => {
    const testApp = new Hoa({ name: 'TestApp' })
    testApp.extend(tinyRouter())

    // Default realm uses app.name
    testApp.get('/realm-default/*', basicAuth({ username: 'u', password: 'p' }))
    testApp.get('/realm-default/*', (ctx) => { ctx.res.body = 'ok' })

    let req = new Request('http://localhost/realm-default/a')
    let res = await testApp.fetch(req)
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toBe('Basic realm="TestApp"')

    // Custom realm
    testApp.get('/realm-custom/*', basicAuth({ username: 'u', password: 'p', realm: 'CustomRealm' }))
    testApp.get('/realm-custom/*', (ctx) => { ctx.res.body = 'ok' })

    req = new Request('http://localhost/realm-custom/a')
    res = await testApp.fetch(req)
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toBe('Basic realm="CustomRealm"')

    // Realm with special characters (escaped quotes)
    testApp.get('/realm-escape/*', basicAuth({ username: 'u', password: 'p', realm: 'My "Special" Realm' }))
    testApp.get('/realm-escape/*', (ctx) => { ctx.res.body = 'ok' })

    req = new Request('http://localhost/realm-escape/a')
    res = await testApp.fetch(req)
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toBe('Basic realm="My \\"Special\\" Realm"')
  })

  it('should handle UTF-8 credentials (Chinese, mixed, emoji)', async () => {
    const encodeUtf8Credential = (username: string, password: string) => {
      const credentials = `${username}:${password}`
      const utf8Bytes = new TextEncoder().encode(credentials)
      const binaryString = String.fromCharCode(...utf8Bytes)
      return btoa(binaryString)
    }

    const testApp = new Hoa({ name: 'UTF8Test' })
    testApp.extend(tinyRouter())

    // Chinese credentials
    testApp.get('/utf8-cn/*', basicAuth({ username: '账号', password: '密码' }))
    testApp.get('/utf8-cn/*', (ctx) => { ctx.res.body = 'cn-ok' })

    let req = new Request('http://localhost/utf8-cn/test')
    req.headers.set('Authorization', `Basic ${encodeUtf8Credential('账号', '密码')}`)
    let res = await testApp.fetch(req)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('cn-ok')

    // Mixed ASCII and UTF-8
    testApp.get('/utf8-mix/*', basicAuth({ username: 'user用户', password: 'pass密码123' }))
    testApp.get('/utf8-mix/*', (ctx) => { ctx.res.body = 'mix-ok' })

    req = new Request('http://localhost/utf8-mix/test')
    req.headers.set('Authorization', `Basic ${encodeUtf8Credential('user用户', 'pass密码123')}`)
    res = await testApp.fetch(req)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('mix-ok')

    // Emoji credentials
    testApp.get('/utf8-emoji/*', basicAuth({ username: 'user🔐', password: 'pass🔑' }))
    testApp.get('/utf8-emoji/*', (ctx) => { ctx.res.body = 'emoji-ok' })

    req = new Request('http://localhost/utf8-emoji/test')
    req.headers.set('Authorization', `Basic ${encodeUtf8Credential('user🔐', 'pass🔑')}`)
    res = await testApp.fetch(req)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('emoji-ok')

    // Wrong UTF-8 credentials
    req = new Request('http://localhost/utf8-cn/test')
    req.headers.set('Authorization', `Basic ${encodeUtf8Credential('错误', '凭证')}`)
    res = await testApp.fetch(req)
    expect(res.status).toBe(401)
  })
})
