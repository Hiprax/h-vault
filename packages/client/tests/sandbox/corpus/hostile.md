<!--
  A committed corpus of hostile markdown.

  Every entry below is a vector that a renderer running in the application's
  origin would hand an attacker the unlocked vault key with. The suite asserts
  what a real browser BUILT FROM THE OUTPUT contains — the rendered DOM — and
  never what the sanitizer returned, because the question is what a parser does
  with the output, not what a library said about it.

  Keep this file as data. Nothing here is generated, and nothing here may be
  "tidied": each line is a separate code path.
-->

# Hostile document

A raw script element:

<script>window.__pwned = 1;</script>

An image with an error handler, which is the classic way to run script without a
script element:

<img src="x" onerror="window.__pwned = 2">

A link whose scheme executes in the opening origin:

<a href="javascript:window.__pwned=3">raw html javascript link</a>

The markdown-NATIVE spelling of the same thing. It reaches the tree through
`remark-rehype` without ever touching `rehype-raw`, so a pipeline that only
sanitised raw HTML would let this through — and it is the likelier real-world
vector of the two:

[markdown native](javascript:window.__pwned=4)

A frame, an embedded object and a form, each of which can fetch or submit:

<iframe src="https://example.invalid/"></iframe>
<object data="https://example.invalid/"></object>
<form action="https://example.invalid/"><input name="q" value="v"></form>

An inline SVG, whose `onload` runs where an `<img src="...svg">` would not:

<svg onload="window.__pwned = 5"><circle r="1" /></svg>

A style attribute, which GitHub strips and which is a phishing surface on its
own (an absolutely-positioned overlay over the application's chrome):

<p style="position:fixed;top:0;left:0;width:100vw;height:100vh">styled</p>

A data-URI script source:

<script src="data:text/javascript,window.__pwned=6"></script>

A stylesheet, whose TEXT leaks into the page as a paragraph if the element is
merely unwrapped rather than removed:

<style>body { --leaked: "this must not be readable text"; }</style>

DOM clobbering: an element whose id shadows `document.body`, and an input whose
name shadows `document.getElementById`. The sanitizer's default schema defends
against this by prefixing every id and name, and a future custom schema would
silently drop that.

<a id="body">clobber body</a>
<input name="getElementById" value="clobber lookup">

A remote image, which is blocked by the policy rather than by the sanitizer, and
which the reader is told about:

![a tracking pixel](https://example.invalid/pixel.png)

A `<picture>` whose ONLY remote reference is a `srcset` candidate, and not the
first one. The default schema allows `picture` and `source`, allows
`source: ['srcSet']`, and lists no protocol filter for `srcSet` at all, so the
URL survives exactly as written and the request is refused by `img-src`. A sweep
that looked at `img[src]` alone saw nothing here.

<picture><source srcset="local-narrow.png 1x, https://example.invalid/wide.png 2x"><img src="local-narrow.png" alt="a responsive image"></picture>

## Things that must SURVIVE, because a README is supposed to look like one

| column | meaning |
| ------ | ------- |
| one    | first   |
| two    | second  |

- [x] a completed task
- [ ] an incomplete one

~~struck through~~, an autolink https://example.com/auto, and a footnote[^note].

```js
const highlighted = 1;
```

[^note]: The footnote body, which GFM renders at the end.
