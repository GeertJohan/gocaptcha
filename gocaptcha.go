package gocaptcha

import (
	"log"
	"strings"
)

type GoCaptcha struct {
	privatekey        string
	remoteip          string
	lastresultMessage string
	lastresult        bool
}

// NewGoCaptha creates a new GoCaptcha object.
// Privatekey is the api key.
// Remoteaddr is expected to be an ip address, or RemoteAddr as set on an http.Request object.
// Warning: at this moment only IPv4 remoteaddr is supported. Major bug!
func NewGoCaptcha(privatekey string, remoteaddr string) *GoCaptcha {
	//++ WARNING: This will NOT work with IPv6. Major bug!
	//++ TODO(GeertJohan): pickup the ip properly.
	remoteip := strings.SplitN(remoteaddr, ":", 1)[0]
	gc := &GoCaptcha{
		privatekey: privatekey,
		remoteip:   remoteip,
	}
	return gc
}

// http://www.google.com/recaptcha/api/verify
// privatekey
// remoteip
// challenge
// response
