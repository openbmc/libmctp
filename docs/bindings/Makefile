vendor-ibm-astlpc.html: vendor-ibm-astlpc.md
	markdown2 \
	  --extras=code-friendly \
	  --extras=fenced-code-blocks \
	  --extras=tables \
	  $< > $@

.PHONY: clean
clean:
	$(RM) vendor-ibm-astlpc.html
