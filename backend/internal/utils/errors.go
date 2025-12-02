package utils

// APIError represents a structured error that can be safely returned to clients.
type APIError struct {
	StatusCode int    `json:"-"`
	Message    string `json:"message"`
}

func (e *APIError) Error() string {
	return e.Message
}

// NewAPIError constructs a new APIError instance.
func NewAPIError(statusCode int, message string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
	}
}

// ValidationError represents a 400 Bad Request error.
func ValidationError(message string) *APIError {
	return NewAPIError(400, message)
}

// UnauthorizedError represents a 401 Unauthorized error.
func UnauthorizedError(message string) *APIError {
	return NewAPIError(401, message)
}

// ForbiddenError represents a 403 Forbidden error.
func ForbiddenError(message string) *APIError {
	return NewAPIError(403, message)
}

// NotFoundError represents a 404 Not Found error.
func NotFoundError(message string) *APIError {
	return NewAPIError(404, message)
}

// InternalServerError represents a 500 Internal Server Error.
func InternalServerError(message string) *APIError {
	return NewAPIError(500, message)
}








