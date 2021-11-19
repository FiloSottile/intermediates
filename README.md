# filippo.io/intermediates

Package intermediates embeds a list of known unexpired, unrevoked
intermediate certificates chaining to roots with Websites trust in the
Mozilla Root Program.

This dataset is useful to establish connections to misconfigured servers that
fail to provide a full certificate chain but provide a valid, publicly
trusted end-entity certificate. Some browsers implement similar strategies to
successfully establish connections to these sites.

https://pkg.go.dev/filippo.io/intermediates

This is not an official or supported Google product, just some code that
happens to be owned by Google.
