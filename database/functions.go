// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

// RemoveAllIdentities clears all public keys from the database.
func (db *Db) RemoveAllIdentities() error {
	a, err := db.GetAllIdentities()
	if err != nil {
		return err
	}

	for _, address := range a {
		db.RemoveIdentity(address)
	}

	return nil
}
