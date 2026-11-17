package system

import (
	"fmt"
	"os/user"
	"strconv"
)

// User is a Linux account a site runs as.
type User struct {
	Name   string
	UID    uint32
	GID    uint32
	Groups []uint32
	Home   string
}

// LookupUser resolves name from the system's user database.
func LookupUser(name string) (User, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return User{}, fmt.Errorf("look up user %s: %w", name, err)
	}

	return fromAccount(account)
}

// CurrentUser returns the user the agent (or a test) runs as.
func CurrentUser() (User, error) {
	account, err := user.Current()
	if err != nil {
		return User{}, fmt.Errorf("look up current user: %w", err)
	}

	return fromAccount(account)
}

func fromAccount(account *user.User) (User, error) {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return User{}, fmt.Errorf("parse uid %q: %w", account.Uid, err)
	}

	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return User{}, fmt.Errorf("parse gid %q: %w", account.Gid, err)
	}

	result := User{Name: account.Username, UID: uint32(uid), GID: uint32(gid), Home: account.HomeDir}

	groupIDs, err := account.GroupIds()
	if err != nil {
		return result, nil
	}

	for _, id := range groupIDs {
		if value, err := strconv.ParseUint(id, 10, 32); err == nil {
			result.Groups = append(result.Groups, uint32(value))
		}
	}

	return result, nil
}
