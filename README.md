# mega-gemini

A Gemini browser for the MEGA65. Type a `gemini://` address, read the
page on the 80-column screen, follow its links, keep bookmarks, and save
pages to disk. Connections use TLS 1.3, and each server's key is
remembered the first time you visit, so a changed key is refused.

## Starting

Mount `GEMINI.D81` and type `RUN "GEMINI"`, or choose Gemini from the
[Net-Tools](https://github.com/silent-command/mega-menu) menu. It needs a
network cable and the 8 MB attic RAM.

## Keys

Reading a page:

| Key | Does |
|---|---|
| CRSR up / down | scroll a line |
| SPACE or CRSR right | page down |
| CRSR left | page up |
| CLR/HOME | top of the page |
| TAB or L | next link |
| SHIFT+TAB or K | previous link |
| RETURN | follow the selected link |
| RUN/STOP | back |
| A | type an address |
| H or HELP | home page |
| M | bookmark this page, or remove the bookmark |
| S | save the page to disk |
| F / B | change the text / background colour |
| Q | quit to BASIC |

At the address prompt:

| Key | Does |
|---|---|
| RETURN | go to the address |
| a number, then RETURN | open that bookmark |
| D and a number, then RETURN | delete that bookmark |
| RUN/STOP | back to the page (on the first prompt, quit to BASIC) |

RUN/STOP also cancels a page that is still loading.

## Credits

Created by Justin Cameron. Apache License 2.0; see [LICENSE](LICENSE)
and [NOTICE](NOTICE).
