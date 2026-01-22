### go-multipassify
Shopify Multipass module for Go

#### Installation
```
go get github.com/yuta1031/go-multipassify
```

#### Usage
```go
import multipassify "github.com/yuta1031/go-multipassify"

	m, err := multipassify.New(SHOPIFY_MULTIPASS_SECRET, jst)
	if err != nil {
		panic(err)
	}
	customerInfo := map[string]any{
		"email": customer.Email,
	}

	url, err := m.GenerateUrl(customerInfo, SHOPIFY_DOMAIN)sify.

    // Generates a URL like:  https://yourstorename.myshopify.com/account/login/multipass/<MULTIPASS-TOKEN>
```