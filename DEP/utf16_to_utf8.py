# output of rp++ tool returns utf16 txt file, convert it to utf8

import codecs

with open("input.txt", "r", encoding="utf-16-le") as f:
    content = f.read()

with open("output.txt", "w", encoding="utf-8") as f:
    f.write(content)
