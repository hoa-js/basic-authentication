## @hoajs/basic-authentication

Basic-Authentication middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/basic-authentication --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import { basicAuthentication } from '@hoajs/basic-authentication'

const app = new Hoa()
app.use(basicAuthentication())

app.use(async (ctx) => {
  ctx.res.body = `Hello, Hoa!`
})

export default app
```

## Documentation

The documentation is available on [hoa-js.com](https://hoa-js.com/middleware/basic-authentication.html)

## Test (100% coverage)

```sh
$ npm test
```

## License

MIT
