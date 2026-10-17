# Same-origin image

A picture addressed to this server's own API. Inside the isolated document
`'self'` would name this server, so the frame's policy gives images no
same-origin source at all: the browser refuses this one on `img-src` and the
request never leaves it.

![a picture addressed to the API](/api/v1/csrf-token?x)

Text after the picture, so a renderer that dropped the element can be told
apart from one that kept it.
