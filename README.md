# AES-GMAC for COSE

The internet-draft is tracked as [draft-sipos-cose-gmac](https://datatracker.ietf.org/doc/draft-sipos-cose-gmac/).

A local build of the current main branch is available [draft-sipos-cose-gmac.html](https://briansipos.github.io/cose-gmac/draft-sipos-cose-gmac.html).
A difference from the datatracker draft and this local version can be [viewed side-by-side](https://author-tools.ietf.org/diff?doc_1=draft-sipos-cose-gmac&url_2=https://briansipos.github.io/cose-gmac/draft-sipos-cose-gmac.txt&raw=1).

Prerequisites to building can be installed on Ubuntu with:
```
sudo apt-get install -y cmake python3-pip python3-wheel ruby xmlstarlet aspell
pip3 install xml2rfc
```

Then the document can be built with
```
cmake -S . -B build/default
cmake --build build/default
```
finally opened with
```
xdg-open build/default/draft-*.html
```
