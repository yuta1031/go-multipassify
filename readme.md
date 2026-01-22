### go-multipassify
Shopify Multipass module for Go

#### Installation
```
go get github.com/yuta1031/go-multipassify
```

#### Usage
```go
import multipassify "github.com/yuta1031/go-multipassify"


    // specify your location or pass nil to use the local location
	m, err := multipassify.New("[SHOPIFY_MULTIPASS_SECRET]", nil)
	if err != nil {
		panic(err)
	}
	customerInfo := map[string]any{
		"email": "test@example.com",
	}

	url, err := m.GenerateUrl(customerInfo, "[SHOPIFY_DOMAIN]")
    if err != nil {
		panic(err)
	}

    // Generates a URL like:  https://yourstorename.myshopify.com/account/login/multipass/<MULTIPASS-TOKEN>
```