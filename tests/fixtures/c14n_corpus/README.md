# Canonicalization corpus

`caseN.xml` inputs with the expected canonical output of the whole document
produced by libxml2 (`xmllint --c14n`, `--c14n11`, `--exc-c14n`). xmllint
emits the `#WithComments` variants. Regenerate with:

```sh
for f in case*.xml; do b=${f%.xml}; xmllint --c14n $f > $b.c14n; xmllint --c14n11 $f > $b.c14n11; xmllint --exc-c14n $f > $b.exc-c14n; done
```
