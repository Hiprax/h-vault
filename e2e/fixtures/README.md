# Field notes

A stored document, rendered by the sandbox so this file's markdown never touches
the origin that holds the vault key.

| Format | Rendered by | Executes |
| ------ | ----------- | -------- |
| Markdown | remark + rehype-sanitize | nothing |
| CSV | a table of text nodes | nothing |
| PNG | an `<img>` from a blob URL | nothing |

## Checklist

- [x] tables survive the sanitizer
- [x] task lists survive the sanitizer
- [ ] nothing here is ever fetched

~~Struck through~~ and a [link out](https://example.com/field-notes) that has to
be confirmed before it opens.
