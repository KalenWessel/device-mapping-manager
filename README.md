# device-mapping-manager

This maps and enables devices into containers running on docker swarm. It is currently only compatible with linux systems that use cgroup v1 and v2.

## Fork notes

Fork of [allfro/device-mapping-manager](https://github.com/allfro/device-mapping-manager), which
has been unmaintained since July 2023. Upstream only reacts to container `start` events, so any
container already running when this service starts never receives its device rules. On Swarm that
is common — a node-wide event can start a consumer before this service is up — and the affected
container then runs indefinitely getting `EPERM` on its device. Upstream PRs
[#14](https://github.com/allfro/device-mapping-manager/pull/14) and
[#16](https://github.com/allfro/device-mapping-manager/pull/16) both propose a startup scan and
have sat unmerged since 2024.

Changes here relative to upstream:

- Scan already-running containers at startup, so a late start is no longer permanent.
- Subscribe to the event stream *before* scanning. Both upstream PRs scan first, which leaves a
  window where a container starting mid-scan is missed by the scan and the subscription alike.
- Deduplicate by container ID and pid, so the scan/event overlap is not processed twice while a
  container restarted in place is still handled.
- Skip privileged containers, which already have unrestricted device access.
- Skip mounts of the entire `/dev` tree. Walking it adds a rule per device node, granting far more
  than the mount implies and bloating the eBPF program.

Note that `AddDeviceRules` prepends to the existing eBPF program rather than replacing rules, so
each pass over a long-lived container grows its program. This is bounded in practice because a
scan runs once per service start.

# Installation

`docker stack deploy -c docker-compose.yml dmm`

# Usage

```yaml
version: "3.8"

services:
  rdesktop:
    image: lscr.io/linuxserver/rdesktop
    volumes:
      - /dev/dri:/dev/dri
    ports:
      - 3389:3389

```
