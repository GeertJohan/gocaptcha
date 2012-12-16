package gocaptcha

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"text/template"
)

var captchaHtml *template.Template

func init() {
	var err error
	captchaHtml, err = template.New("CaptchaHtml").Parse(`
<script type="text/javascript" src="http://www.google.com/recaptcha/api/challenge?k={{.PublicKey}}&error={{.ErrorCode}}"></script>
<noscript>
	<iframe src="http://www.google.com/recaptcha/api/noscript?k={{.PublicKey}}&error={{.ErrorCode}}" height="300" width="500" frameborder="0"></iframe><br>
	<textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
	<input type="hidden" name="recaptcha_response_field" value="manual_challenge">
</noscript>
`)
	if err != nil {
		fmt.Printf("Error parsing CaptchaHtml template.")
		os.Exit(-1)
	}
}

// A GoCaptcha object identifies a single reCAPTCHA session (for one client).
// It is possible to store this object on a session activity and re-use it lateron for verification.
// This object keeps track of faulty verifications and makes sure any newly generated html contains an error message for the end-user, as provided by reCAPTCHA.
// Once a reCAPTCHA response was successfully verified this object should be discarded.
type GoCaptcha struct {
	publickey     string
	privatekey    string
	lastErrorCode string
	lastResult    bool
}

// NewGoCaptha creates a new GoCaptcha object.
// Privatekey is the api key to be used with reCAPTCHA.
func NewGoCaptcha(publickey string, privatekey string) *GoCaptcha {
	gc := &GoCaptcha{
		publickey:  publickey,
		privatekey: privatekey,
	}
	return gc
}

// Generate the reCAPTCHA html for this session and write it to the given io.Writer.
func (gc *GoCaptcha) WriteHtml(w io.Writer) error {
	err := captchaHtml.Execute(w, struct {
		PublicKey string
		ErrorCode string
	}{gc.publickey, gc.lastErrorCode})
	return err
}

// Generate the reCAPTCHA html for this session and return it as string.
// If error is not nil then something went wrong and string is empty.
func (gc *GoCaptcha) HtmlString() (string, error) {
	buf := new(bytes.Buffer)
	err := gc.WriteHtml(buf)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Generate the reCAPTCHA html for this session and return it as byteslice.
// If error is not nil then something went wrong and the byteslice is empty.
func (gc *GoCaptcha) HtmlByteSlice() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := gc.WriteHtml(buf)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// Verify calls the reCAPTCHA API to verify if the given response by end-user is correct.
// Any returned error indicates a unsuccessfull api call. It does not indicate that the reCAPTCHA response by the end-user was faulty.
// Any returned error value is not to be shown to the end-user.
// When the error is nil, then response=false indicates that the reCAPTCHA response by the end-user was faulty.
// End-user will be notified of a faulty reCAPTCHA response when re-using this GoCaptcha object to generate html code again.
// 
// Expected parameters:
// challenge string, form value as sent by the http request. (Set by the reCAPTCHA in the end-users browser.)
// response string, form value as sent by the http request. (The answer given by the end-user.)
// remoteaddr string, The http.Request.RemoteAddr (e.g. "127.0.0.1:45435") from the client's endpoint.
func (gc *GoCaptcha) Verify(challenge string, response string, remoteaddr string) (bool, error) {
	if gc.lastResult {
		return false, errors.New("This GoCaptcha session has already been successfully verified. Please create a new GoCaptcha session.")
	}

	remoteip, _, err := net.SplitHostPort(remoteaddr)
	if err != nil {
		return false, err
	}

	apiRequestValues := url.Values{}
	apiRequestValues.Set("privatekey", gc.privatekey)
	apiRequestValues.Set("remoteip", remoteip)
	apiRequestValues.Set("challenge", challenge)
	apiRequestValues.Set("response", response)
	apiResponse, err := http.PostForm("https://www.google.com/recaptcha/api/verify", apiRequestValues)
	if err != nil {
		return false, err
	}
	defer apiResponse.Body.Close()
	reader := bufio.NewReader(apiResponse.Body)

	// read first line
	line1, err := reader.ReadString('\n')
	if err != nil {
		return false, errors.New("Received unexpected result value from reCAPTCHA API.")
	}
	switch line1 {
	case "true\n":
		gc.lastResult = true
		gc.lastErrorCode = ""
		return true, nil

	case "false\n":
		// read second line
		line2, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, errors.New("Received unexpected result value from reCAPTCHA API.")
		}
		gc.lastErrorCode = line2

	default:
		return false, errors.New("Received unexpected result value from reCAPTCHA API.")
	}

	return false, nil
}
