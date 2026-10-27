// Package fsperm keeps files private to the user who runs the process and makes directory
// entries durable, with one meaning on every OS: mode bits on Unix, the owner and a protected
// DACL on Windows, where Go reports no mode bits beyond the read-only attribute.
package fsperm
