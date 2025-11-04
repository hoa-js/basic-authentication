## @hoajs/basic-auth

Basic Authentication middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/basic-auth --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import { basicAuth } from '@hoajs/basic-auth'

const app = new Hoa()
app.use(basicAuth({
  username: 'admin',
  password: '123456'
}))

app.use(async (ctx) => {
  ctx.res.body = `Hello, Hoa!`
})

export default app
```

## Documentation

The documentation is available on [hoa-js.com](https://hoa-js.com/middleware/basic-auth.html)

## Test (100% coverage)

```sh
$ npm test
```

## License

MIT
