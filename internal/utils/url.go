package utils

import (
	"errors"
	"fmt"
	"net/url"
)

type UrlBuilder struct {
	Scheme string
}

func (b UrlBuilder) String(val string) (*url.URL, error) {
	res, err := url.Parse(val)
	if err != nil {
		return nil, err
	}
	if b.Scheme != "" && res.Scheme != b.Scheme {
		str := fmt.Sprintf("only the '%s' scheme is allowed", b.Scheme)
		return nil, errors.New(str)
	}
	return res, nil
}

// vim: set ts=4 sw=4 noexpandtab:
