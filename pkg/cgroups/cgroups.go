package cgroups

import (
	"os"
	"fmt"
	"strings"
	"net"
	"syscall"
        "golang.org/x/sys/unix"
)

// PeerCredKey is used as the context key for storing peer credentials.
var PeerCredKey = &struct{}{}

type PeerCred struct {
	PID int
	UID int
	GID int
}

func GetPeerCred(c net.Conn) (*PeerCred, error) {
    sc, ok := c.(syscall.Conn)
    if !ok {
        return nil, fmt.Errorf("not a syscall.Conn")
    }

    raw, err := sc.SyscallConn()
    if err != nil {
        return nil, fmt.Errorf("SyscallConn: %w", err)
    }

    var cred *PeerCred
    var ctrlErr error

    // Control runs a function with the underlying FD.
    if err := raw.Control(func(fd uintptr) {
        ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
        if err != nil {
            ctrlErr = err
            return
        }
        cred = &PeerCred{PID: int(ucred.Pid), UID: int(ucred.Uid), GID: int(ucred.Gid)}
    }); err != nil {
        return nil, fmt.Errorf("raw.Control: %w", err)
    }
    if ctrlErr != nil {
        return nil, fmt.Errorf("getsockopt SO_PEERCRED: %w", ctrlErr)
    }
    return cred, nil
}

func DeriveParentFromProcCgroupfs(pc *PeerCred) (string, error) {
    if pc == nil || pc.PID == 0 {
        return "", fmt.Errorf("no peer credentials")
    }

    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pc.PID))
    if err != nil {
        return "", fmt.Errorf("read cgroup: %w", err)
    }

    var path string
    for _, ln := range strings.Split(string(data), "\n") {
        if ln == "" { continue }
        parts := strings.SplitN(ln, ":", 3)
        if len(parts) < 3 { continue }
        if strings.HasPrefix(ln, "0::") {
            path = parts[2]
            break
        }
        if parts[1] == "cpu" { path = parts[2] }
    }
    if path == "" {
        return "", fmt.Errorf("no cgroup path found")
    }
    return path, nil
}

func DeriveParentFromProc(pc *PeerCred) (string, error) {
	if pc == nil || pc.PID <= 0 {
		return "", fmt.Errorf("no peer credentials")
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pc.PID))
	if err != nil {
		return "", fmt.Errorf("read cgroup: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	// Prefer cgroup v2 unified line "0::/path"
	var cgPath string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) < 3 {
			continue
		}
		controller, path := parts[1], parts[2]

		// v2 line
		if strings.HasPrefix(ln, "0::") {
			cgPath = path
			break
		}
		// v1 systemd controller
		if controller == "name=systemd" {
			cgPath = path
			// keep searching in case a v2 line appears later; if not, this stays
		}
	}

	if cgPath == "" {
		// Fallback: pick a reasonable slice based on UID; user slices typically live under user.slice.
		// Return a single slice *name* (no '/').
		if pc.UID >= 1000 {
			return fmt.Sprintf("user-%d.slice", pc.UID), nil
		}
		return "system.slice", nil
	}

	// Extract the deepest *.slice component and return just that unit name.
	segs := strings.Split(strings.TrimPrefix(cgPath, "/"), "/")
	var lastSlice string
	for _, s := range segs {
		if strings.HasSuffix(s, ".slice") {
			lastSlice = s
		}
	}
	if lastSlice != "" {
		return lastSlice, nil // e.g., "user-1000.slice"
	}

	// No *.slice segments found: fallback like above.
	if pc.UID >= 1000 {
		return fmt.Sprintf("user-%d.slice", pc.UID), nil
	}
	return "system.slice", nil
}
