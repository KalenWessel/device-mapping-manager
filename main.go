//go:build linux

package main

// #include "ctypes.h"
import "C"
import (
	"context"
	"device-volume-driver/internal/cgroup"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	_ "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const pluginId = "dvd"
const rootPath = "/host"

func Ptr[T any](v T) *T {
	return &v
}

func main() {
	listenForMounts()
}

func getDeviceInfo(devicePath string) (string, int64, int64, error) {
	var stat unix.Stat_t

	if err := unix.Stat(devicePath, &stat); err != nil {
		log.Println(err)
		return "", -1, -1, err
	}

	var deviceType string

	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		deviceType = "b"
	case unix.S_IFCHR:
		deviceType = "c"
	default:
		log.Println("aborting: device is neither a character or block device")
		return "", -1, -1, fmt.Errorf("unsupported device type... aborting")
	}

	major := int64(unix.Major(stat.Rdev))
	minor := int64(unix.Minor(stat.Rdev))

	log.Printf("Found device: %s %s %d:%d\n", devicePath, deviceType, major, minor)

	return deviceType, major, minor, nil
}

func listenForMounts() {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	if err != nil {
		log.Fatal(err)
	}

	defer cli.Close()

	// Subscribe before scanning. A container that starts between the scan and the subscription
	// would otherwise be missed by both, and would never receive its device rules.
	msgs, errs := cli.Events(
		ctx,
		types.EventsOptions{Filters: filters.NewArgs(filters.Arg("event", "start"))},
	)

	// Keyed by container ID and pid, so a container restarted in place is treated as new work
	// while the scan/event overlap is still deduplicated.
	processed := make(map[string]bool)

	scanRunningContainers(ctx, cli, processed)

	for {
		select {
		case err := <-errs:
			log.Fatal(err)
		case msg := <-msgs:
			processContainer(ctx, cli, msg.Actor.ID, processed)
		}
	}
}

// scanRunningContainers applies device rules to containers that were already running when this
// process started. Without it, anything started before this process never gets its rules, which
// on Swarm means a container can run indefinitely unable to open its device.
func scanRunningContainers(ctx context.Context, cli *client.Client, processed map[string]bool) {
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})

	if err != nil {
		log.Printf("unable to list running containers: %v\n", err)
		return
	}

	log.Printf("Scanning %d running container(s) for device mounts\n", len(containers))

	for _, container := range containers {
		processContainer(ctx, cli, container.ID, processed)
	}
}

func processContainer(ctx context.Context, cli *client.Client, containerId string, processed map[string]bool) {
	info, err := cli.ContainerInspect(ctx, containerId)

	if err != nil {
		log.Println(err)
		return
	}

	pid := info.State.Pid

	if pid == 0 {
		log.Printf("%s has no running process... skipping\n", containerId)
		return
	}

	key := fmt.Sprintf("%s:%d", containerId, pid)

	if processed[key] {
		return
	}

	processed[key] = true

	// Privileged containers already have unrestricted device access, and rewriting their filter
	// only bloats the eBPF program.
	if info.HostConfig != nil && info.HostConfig.Privileged {
		log.Printf("%s is privileged and already has device access... skipping\n", containerId)
		return
	}

	version, err := cgroup.GetDeviceCGroupVersion("/", pid)

	log.Printf("The cgroup version for process %d is: %v\n", pid, version)

	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("Checking mounts for process %d\n", pid)

	processMounts(containerId, info.Mounts, pid, version)
}

func processMounts(containerId string, mounts []types.MountPoint, pid int, version int) {
	api, err := cgroup.New(version)

	if err != nil {
		log.Println(err)
		return
	}

	for _, mount := range mounts {
		log.Printf(
			"%s/%v requested a volume mount for %s at %s\n",
			containerId, pid, mount.Source, mount.Destination,
		)

		if !strings.HasPrefix(mount.Source, "/dev") {
			log.Printf("%s is not a device... skipping\n", mount.Source)
			continue
		}

		// Walking the whole device tree would add a rule per node, granting far more than the
		// mount implies and bloating the eBPF program. Containers that mount all of /dev are
		// privileged in practice and do not need rules.
		if path.Clean(mount.Source) == "/dev" {
			log.Printf("%s is the entire device tree... skipping\n", mount.Source)
			continue
		}

		cgroupPath, sysfsPath, err := api.GetDeviceCGroupMountPath("/", pid)

		if err != nil {
			log.Println(err)
			continue
		}

		cgroupPath = path.Join(rootPath, sysfsPath, cgroupPath)

		log.Printf("The cgroup path for process %d is at %v\n", pid, cgroupPath)

		if fileInfo, err := os.Stat(mount.Source); err != nil {
			log.Println(err)
			continue
		} else {
			if fileInfo.IsDir() {
				err := filepath.Walk(mount.Source,
					func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						} else if info.IsDir() {
							return nil
						} else if err = applyDeviceRules(api, path, cgroupPath, pid); err != nil {
							log.Println(err)
						}
						return nil
					})
				if err != nil {
					log.Println(err)
				}
			} else {
				if err = applyDeviceRules(api, mount.Source, cgroupPath, pid); err != nil {
					log.Println(err)
				}
			}
		}
	}
}

func applyDeviceRules(api cgroup.Interface, mountPath string, cgroupPath string, pid int) error {
	deviceType, major, minor, err := getDeviceInfo(mountPath)

	if err != nil {
		log.Println(err)
		return err
	} else {
		log.Printf("Adding device rule for process %d at %s\n", pid, cgroupPath)
		err = api.AddDeviceRules(cgroupPath, []cgroup.DeviceRule{
			{
				Access: "rwm",
				Major:  Ptr[int64](major),
				Minor:  Ptr[int64](minor),
				Type:   deviceType,
				Allow:  true,
			},
		})

		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}
