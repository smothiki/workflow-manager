package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-swagger/go-swagger/client"
	"github.com/go-swagger/go-swagger/httpkit"

	strfmt "github.com/go-swagger/go-swagger/strfmt"
)

// PingReader is a Reader for the Ping structure.
type PingReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the recieved o.
func (o *PingReader) ReadResponse(response client.Response, consumer httpkit.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewPingOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	default:
		result := NewPingDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	}
}

// NewPingOK creates a PingOK with default headers values
func NewPingOK() *PingOK {
	return &PingOK{}
}

/*PingOK handles this case with default header values.

server ping success
*/
type PingOK struct {
}

func (o *PingOK) Error() string {
	return fmt.Sprintf("[GET /ping][%d] pingOK ", 200)
}

func (o *PingOK) readResponse(response client.Response, consumer httpkit.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPingDefault creates a PingDefault with default headers values
func NewPingDefault(code int) *PingDefault {
	return &PingDefault{
		_statusCode: code,
	}
}

/*PingDefault handles this case with default header values.

unexpected error
*/
type PingDefault struct {
	_statusCode int
}

// Code gets the status code for the ping default response
func (o *PingDefault) Code() int {
	return o._statusCode
}

func (o *PingDefault) Error() string {
	return fmt.Sprintf("[GET /ping][%d] ping default ", o._statusCode)
}

func (o *PingDefault) readResponse(response client.Response, consumer httpkit.Consumer, formats strfmt.Registry) error {

	return nil
}