# runc

TypeScript client for [`runc`](https://github.com/opencontainers/runc).

## Installation

First, ensure you have installed the `runc` command-line interface.

Next, install with your preferred package manager:

```shell
$ yarn add @containers-js/runc
$ npm install @containers-js/runc
$ pnpm add @containers-js/runc
```

## Usage

```typescript
import {RunC} from '@containers/runc'

const client = new RunC()

await client.run('example', 'library/ubuntu', {...})
```

## License

MIT License, see `LICENSE`
