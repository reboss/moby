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

// deriveParentFromProc finds the deepest ".slice" in the caller's cgroup path
// and returns it as a systemd slice path, e.g. "user.slice/user-1000.slice".
func DeriveParentFromProc(pc *PeerCred) (string, error) {
    if pc == nil || pc.PID == 0 {
        return "", fmt.Errorf("no peer credentials")
    }
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pc.PID))
    if err != nil {
        return "", fmt.Errorf("read cgroup: %w", err)
    }
    // On cgroup v2, there is one line like: "0::/user.slice/user-1000.slice/session-6.scope"
    // On cgroup v1, systemd is "name=systemd:/user.slice/user-1000.slice/session-6.scope"
    lines := strings.Split(string(data), "\n")
    var path string
    for _, ln := range lines {
        if ln == "" {
            continue
        }
        parts := strings.SplitN(ln, ":", 3)
        if len(parts) < 3 {
            continue
        }
        controller, cgPath := parts[1], parts[2]
        if controller == "" || controller == "name=systemd" || controller == "" /* v2 */ {
            path = cgPath
            // prefer v2 line if present; break on first match
            if strings.HasPrefix(ln, "0::") {
                break
            }
        }
    }
    if path == "" {
        return "", fmt.Errorf("no cgroup path found")
    }
    // Extract slice segments ending with ".slice"
    segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
    var slices []string
    for _, s := range segs {
        if strings.HasSuffix(s, ".slice") {
            slices = append(slices, s)
        }
    }
    if len(slices) == 0 {
        // Fallback to uid mapping
        return fmt.Sprintf("user.slice/user-%d.slice", pc.UID), nil
    }
    // Build "slice path" up to the deepest slice (exclude scopes/services)
    // e.g., user.slice/user-1000.slice
    var b strings.Builder
    for i, s := range slices {
        if i > 0 {
            b.WriteString("/")
        }
        b.WriteString(s)
    }
    return b.String(), nil
}
