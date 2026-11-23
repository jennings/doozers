//! CommonMark to the text a screen reader should read, for the web channel's live region.

use pulldown_cmark::{Event, LinkType, Tag, TagEnd, TextMergeStream};

use super::strip_controls;

/// Reduces CommonMark to the blocks of plain text a screen reader reads aloud, one string per
/// paragraph, heading, list item, code block, or table row.
///
/// - Styling, link targets, and URLs are dropped: a link reads as its text alone (an autolink, whose
///   text is its URL, as nothing), an image as its alt text (`image` without one).
/// - Code, inline and in blocks, is kept as text.
/// - A table row reads as its cells separated by commas.
/// - Raw HTML is kept as literal text.
/// - Control characters other than tab and newline are dropped, and blocks with no text are left
///   out.
pub fn spoken_text(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    // The open images' alt text, so an empty one can read as `image`.
    let mut images: Vec<usize> = Vec::new();
    // Whether the text being read is an autolink's URL.
    let mut autolink = false;
    for event in TextMergeStream::new(super::parser(markdown)) {
        match event {
            Event::Text(_) if autolink => {}
            Event::Text(text) | Event::Code(text) | Event::Html(text) | Event::InlineHtml(text) => {
                current.push_str(&strip_controls(&text));
            }
            Event::Start(Tag::Link { link_type, .. }) => {
                autolink = matches!(link_type, LinkType::Autolink | LinkType::Email);
            }
            Event::End(TagEnd::Link) => autolink = false,
            Event::SoftBreak | Event::HardBreak => current.push(' '),
            Event::Start(Tag::Image { .. }) => images.push(current.len()),
            Event::End(TagEnd::Image) => {
                if images.pop() == Some(current.len()) {
                    current.push_str("image");
                }
            }
            Event::Start(Tag::TableCell) => {
                if !current.trim().is_empty() {
                    current.push_str(", ");
                }
            }
            Event::Start(tag) if is_block(&tag) => flush(&mut blocks, &mut current),
            Event::End(tag) if is_block_end(tag) => flush(&mut blocks, &mut current),
            Event::Rule => flush(&mut blocks, &mut current),
            _ => {}
        }
    }
    flush(&mut blocks, &mut current);
    blocks
}

/// Ends the block being read, if it has any text.
fn flush(blocks: &mut Vec<String>, current: &mut String) {
    let text = current.split_whitespace().collect::<Vec<_>>().join(" ");
    current.clear();
    if !text.is_empty() {
        blocks.push(text);
    }
}

/// Whether `tag` starts a block, as opposed to styling or a link inside one.
fn is_block(tag: &Tag<'_>) -> bool {
    !matches!(
        tag,
        Tag::Emphasis
            | Tag::Strong
            | Tag::Strikethrough
            | Tag::Superscript
            | Tag::Subscript
            | Tag::Link { .. }
            | Tag::Image { .. }
            | Tag::TableCell
    )
}

/// Whether `tag` ends a block.
fn is_block_end(tag: TagEnd) -> bool {
    !matches!(
        tag,
        TagEnd::Emphasis
            | TagEnd::Strong
            | TagEnd::Strikethrough
            | TagEnd::Superscript
            | TagEnd::Subscript
            | TagEnd::Link
            | TagEnd::Image
            | TagEnd::TableCell
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_text_of_each_block() {
        let markdown = "\
# Title

Some *styled* and **strong** words with `code`, a [link](https://example.com/a) and
<https://example.com/b>.

- one
  - nested
- two

```rust
let x = 1;
```

![a chart](https://example.com/c.png) ![](https://example.com/d.png)

---

| a | b |
| - | - |
| 1 | 2 |

<b>raw</b> \u{1b}tail";
        assert_eq!(
            spoken_text(markdown),
            [
                "Title",
                "Some styled and strong words with code, a link and .",
                "one",
                "nested",
                "two",
                "let x = 1;",
                "a chart image",
                "a, b",
                "1, 2",
                "<b>raw</b> tail",
            ]
        );
    }

    #[test]
    fn blank_markdown_has_nothing_to_read() {
        assert!(spoken_text("").is_empty());
        assert!(spoken_text(" \n\n\t").is_empty());
    }
}
