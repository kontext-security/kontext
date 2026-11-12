package hookinstall

// Windows installs no per-user file at system scope yet.
const usersDir = ""

func localHomes(string) []userHome { return nil }

func asOwner(_ userHome, fn func() error) error { return fn() }
