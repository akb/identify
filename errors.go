package identify

import "github.com/pkg/errors"

var (
	ErrorUnauthorized error
	ErrorValidation   error
)

func init() {
	ErrorUnauthorized = errors.New("You are not authorized to perform this action")
	ErrorValidation = errors.New("Provided argument(s) are invalid")
}
