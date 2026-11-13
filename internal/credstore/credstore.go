// Package credstore keeps a secret for the signed-in user in the operating
// system's own store. On Windows that is Credential Manager: a generic
// credential, readable by that user's processes only and kept on this
// machine. The secret is kept as its UTF-8 bytes, and only what this package
// wrote is read back: an entry made with another tool may hold UTF-16, which
// Read refuses rather than return with NUL bytes in it. Other systems have
// their own stores (the macOS keychain is used
// through the security tool elsewhere), so there the functions report
// ErrUnsupported.
package credstore

import "errors"

var (
	// ErrNotFound reports that the store holds no secret under the name.
	ErrNotFound = errors.New("credential not found")
	// ErrUnsupported reports an operating system without a store here.
	ErrUnsupported = errors.New("the credential store is only supported on Windows")
	// ErrNoLogonSession reports a session Windows gives no credential store:
	// one that was not opened with the user's password or at the desktop,
	// such as an SSH session signed in with a key. The user's desktop session
	// has the store.
	ErrNoLogonSession = errors.New("this session has no Windows credential store; use a desktop session of the user")
)

// maxSecretBytes is what Credential Manager takes for one generic credential.
const maxSecretBytes = 2560
