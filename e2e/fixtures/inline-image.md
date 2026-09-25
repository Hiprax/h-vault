# Inline image

An image carried inside the document itself, as a `data:` candidate of a
`<picture>` source. The sanitizer keeps a `srcset` candidate whole, so this is
the path by which a stored document shows a picture without fetching one, and
the policy's `img-src data:` is the only thing that lets the browser decode it.

<picture><source srcset="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAHElEQVR4nGOQz7/x/+vXr/9x0Qz4JEE0w7AwAQAmIchh4xw40gAAAABJRU5ErkJggg=="><img src="not-fetched.png" alt="an inline checkerboard"></picture>

Text after the picture, so a renderer that dropped the element can be told
apart from one that kept it.
