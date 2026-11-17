package state

import (
	"database/sql"
	"errors"
	"fmt"
)

// FirstNodePort and LastNodePort bound the ports Node sites listen on. The port guard (internal/portguard) keeps
// every port in the range for root and the user of the site it is allocated to.
const (
	FirstNodePort = 20000
	LastNodePort  = 29999
)

// NodePorts returns the two ports a Node site switches between, allocating the lowest free pair on first use.
func (s *Store) NodePorts(siteID string) ([2]int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return [2]int{}, err
	}
	defer tx.Rollback()

	ports, err := sitePorts(tx, siteID)
	if err != nil {
		return [2]int{}, err
	}

	for port := FirstNodePort; len(ports) < 2 && port <= LastNodePort; port++ {
		result, err := tx.Exec(`INSERT OR IGNORE INTO node_ports(port, site_id) VALUES (?, ?)`, port, siteID)
		if err != nil {
			return [2]int{}, err
		}
		if inserted, _ := result.RowsAffected(); inserted == 1 {
			ports = append(ports, port)
		}
	}

	if len(ports) < 2 {
		return [2]int{}, fmt.Errorf("no free ports left for Node sites (%d–%d)", FirstNodePort, LastNodePort)
	}

	return [2]int{ports[0], ports[1]}, tx.Commit()
}

// LivePort returns the port Nginx sends a Node site's traffic to, or 0 before its first deploy.
func (s *Store) LivePort(siteID string) (int, error) {
	var port int
	err := s.db.QueryRow(`SELECT port FROM node_ports WHERE site_id = ? AND purpose = 'node' AND live = 1`, siteID).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}

	return port, err
}

// SetLivePort marks port as the site's live port.
func (s *Store) SetLivePort(siteID string, port int) error {
	result, err := s.db.Exec(`UPDATE node_ports SET live = (port = ?) WHERE site_id = ? AND purpose = 'node'`, port, siteID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return fmt.Errorf("site %s has no Node ports", siteID)
	}

	return nil
}

// PortReverb is the purpose of a site's Reverb port; its two release ports (Node, Octane) have purpose "node".
const PortReverb = "reverb"

// SitePort returns the port a site's server for purpose (PortReverb) listens on, allocating the lowest
// free one on first use. It stays the site's until the site is deleted, so the site's .env keeps matching it.
func (s *Store) SitePort(siteID, purpose string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var port int
	err = tx.QueryRow(`SELECT port FROM node_ports WHERE site_id = ? AND purpose = ?`, siteID, purpose).Scan(&port)
	if err == nil {
		return port, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	for port = FirstNodePort; port <= LastNodePort; port++ {
		result, err := tx.Exec(`INSERT OR IGNORE INTO node_ports(port, site_id, purpose) VALUES (?, ?, ?)`, port, siteID, purpose)
		if err != nil {
			return 0, err
		}
		if inserted, _ := result.RowsAffected(); inserted == 1 {
			return port, tx.Commit()
		}
	}

	return 0, fmt.Errorf("no free ports left for %s (%d–%d)", purpose, FirstNodePort, LastNodePort)
}

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func sitePorts(q querier, siteID string) ([]int, error) {
	rows, err := q.Query(`SELECT port FROM node_ports WHERE site_id = ? AND purpose = 'node' ORDER BY port`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}

	return ports, rows.Err()
}

// NodePortUsers maps every allocated port of a stored site to the Linux user the site runs as. Ports allocated for a
// site that was never saved (a create that failed after allocating) are left out, so only root can bind them.
func (s *Store) NodePortUsers() (map[int]string, error) {
	rows, err := s.db.Query(`SELECT node_ports.port, json_extract(sites.spec, '$.user')
FROM node_ports JOIN sites ON sites.id = node_ports.site_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := map[int]string{}
	for rows.Next() {
		var port int
		var user string
		if err := rows.Scan(&port, &user); err != nil {
			return nil, err
		}
		users[port] = user
	}

	return users, rows.Err()
}
