<div align="center">
  <img width="64" src="rebpf-gui/icons/rebpf-on-white.svg"/>
  <h3>Rebpf</h3>
  Per-process network traffic redirection using eBPF (daemon + GUI app).
</div>

<img src="contrib/preview.webp"/>


## Features

- Redirect traffic of specific applications to a specific interface, e.g. in or around a VPN.
- Without affecting the network configuration of any other program.
- Instantly changing settings through the GUI app, no need to restart your apps!
- Using D-Bus interface for integrations and CLI.


## Non-goals

- Complete network isolation: we allow programs to talk to LAN devices.
- Managing network interfaces: at least for now, you have to tell rebpf the
interface name: `busctl call service.rebpf / service.rebpf ChangeOutput s
new-ifname`, although we may add some way to issue notifications on traffic in
the future.


## Why

I wanted something like [Sing-box] with its per-process redirection capability,
but working entirely in kernel space, which looked like a perfect use case for
[eBPF] that I wanted to try out anyway.

If you're here for eBPF, I recommend also checking out [bpftrace], [libbpf],
and [docs.ebpf.io].

<!--

Aya-rs lib was promising at first, but its current direction [seems
questionable](https://github.com/aya-rs/aya/pull/1500), plus there're many
quirks and limitations of which helper function you can use where, which I
guess would be quite hard to consolidate in a usefully succinct abstraction.

-->

[eBPF]: https://ebpf.foundation/what-is-ebpf
[sing-box]: https://github.com/SagerNet/sing-box
[bpftrace]: https://bpftrace.org
[libbpf]: https://www.kernel.org/doc/html/latest/bpf/libbpf/index.html
[docs.ebpf.io]: https://docs.ebpf.io


## How

<details>
<summary>It's complicated. <i>Click to unfold.</i></summary>

[eBPF] is a technology allowing you to run your code directly in the kernel
without needing to write and distribute a full-fledged kernel module or worry
too much about breaking the kernel[^1]. The magic behind eBPF are a verifier
and a JIT compiler, ensuring your code can't loop, can't halt, can't modify
arbitrary kernel data, and doesn't take too long to complete.

[^1]: Note that it still very possible to render your system unusable with
certain types of eBPF programs. They can leak kernel data, alter or block
syscalls, or even alter memory of userspace programs.

eBPF programs run on events. The program context (a slice of kernel data the
program is allowed to read/write) is defined by the program type, basically,
which part of kernel subsystem calls your program. Some program types are only
allowed to observe events (kfuncs, tracing, security monitoring), bus some also
allow affecting the kernel behavior (packet filtering).

As for this project, we want to somehow make egress packets originating from a
socket created by a program matching a user-provided criteria to be
transparently redirected to a specific network interface.

The most obvious way to achieve this on Linux without eBPF would probably involve
network namespaces. A program and its descendants can be completely sandboxed
inside of their own network namespace. Even unprivileged programs
can create their own isolated network namespaces, which might then be
proxied to the global one by the program itself[^2], or be configured by some
privileged daemon in a way we need. The problem is it doesn't seem to be a
solution for already running applications. Linux doesn't provide an obvious way
to transfer arbitrary processes between namespaces from outside the process,
but if we would, for example, circumvent this limitation by injecting some code
using ptrace syscall, but this won't apply instantly nor transparently, due to
sockets created in a parent network namespace, still being bound to it, instead
of the new one, behaving as if the application is still there. So eBPF it is.

[^2]: The trick is to create a socket in a parent namespace and then either
inherit it in a sandboxed process or send it over a UNIX socket. The socket
remains bound to the namespace it was created in.

Checking if a process process falls under a criteria here is relatively
straightforward: we attach a program to [`cgroup/sock_create`] hook, triggered
when a process tries to create a new socket, giving us the ability access the
process's executable path, and compare it to a criteria. Similarly, we can
sweep existing sockets using [`iter/task_file`].

[`cgroup/sock_create`]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK
[`iter/task_file`]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING

Once we've obtained a socket, the most convenient method to redirect traffic
would be to use socket marks to tell the existing kernel routing code to
redirect it to where it needs to go. A privileged userspace application can set
a 32bit SO_MARK on its socket which in turn could be matched dedicated firewall
rules or routing tables, allowing routing such packet via a dedicated
interface. Stateful connection tracking is already there, needed for the
correct treatment of ingress packets.

But there is a problem. We can't just set a mark for an arbitrary userspace
program's socket from an eBPF program (or even from a userspace daemon). As you
already know, eBPF programs are only allowed to modify kernel state in places
where the program type is explicitly allows it to. And, unfortunately, as of
Linux 7.0 eBPF programs can only set marks on TCP sockets for already existing
sockets, missing out on UDP and raw IP sockets, used by ping command to send
ICMP messages, which is unacceptable.

Instead of marking a socket, we could try marking individual packets leaving a
socket, as they still can be traced to the originating socket. Unfortunately,
again, all the hooks on this path are either triggered after a route has
already been selected by Netfilter, or barred from modifying any socket state
like [Netfilter hook].

[netfilter hook]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_NETFILTER

Thus, the we have to resort to redirecting packets ourselves, which is ugly and
error prone as we have to patch up payloads of l2 (ethernet src/dst mac), l3
(ip src/dst addresses, checksum), and even l4 (udp and tcp checksums). While
being unable to use kernel connection state tracking (conntrack), and ARP
neighbor discovery.

So far our program pipeline looks as follows:

- [`syscall`] - Read configuration from userspace, prune the list of tracked sockets.
- [`iter/task_file`] - Sweep through all open sockets and check the processes holding it.
- [`tcx/egress`] - Redirect all egress traffic from the tracked sockets to another user-specified interface.
- [`tcx/ingress`] - Same thing, but redirect ingress traffic.

[`syscall`]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SYSCALL
[`iter/task_file`]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING
[`tcx/egress`]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_ACT
[`tcx/ingress`]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_ACT

To actually redirect a packet it's not enough to know only the interface name.
We have to also keep track of a route it's going to take. For an egress
interface, i.e. the interfaces with the default internet connection, the
required parameters are: ifindex, mac address (l2), ip address (l3), and a mac
address of the next hop, i.e. a mac address of a router. And similarly for the
ingress device.

Moreover, all of these attributes can and will change during the normal
operation, for example, simply disconnecting your device from a network would
remove the output device. Linux notifies userspace of such changes using
multicast netlink messages. We track changes in: interfaces, ip adresses, and
mac addresses of neighboring devices.

A Rebpf daemon watches these changes and updates the eBPF program with new
configuration when needed.

</details>


## Installation

- Manual
  ```sh
  # Install dependencies, see ./rebpf/default.nix and ./rebpf-gui/default.nix
  cargo build --release

  # Rebpf
  install -m 0755 -Dt /usr/bin ./target/release/rebpf
  install -m 0644 -Dt /etc/dbus-1/system.d/ ./contrib/service.rebpf.conf
  install -m 0644 -Dt /usr/share/polkit-1/actions/ ./contrib/service.rebpf.policy
  install -m 0644 -Dt /etc/systemd/system ./contrib/rebpf.service

  # Rebpf-gui
  install -m 0755 -Dt /usr/bin ./target/release/rebpf-gui
  install -m 0755 -Dt /usr/share/applications/ ./contrib/rebpf-gui.desktop
  ```

- NixOS
  ```nix
  # flake.nix
  {
    inputs.rebpf = {
      url = "github:one-d-wide/rebpf";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  }
  ```

  ```nix
  # configuration.nix
  { inputs, ... }:
  {
    imports = [ inputs.rebpf.nixosModules.rebpf ];

    services.rebpf.enable = true;
    programs.rebpf-gui.enable = true;
  }
  ```


## Contributing

- All required dev packages are collected in [./shell.nix], run `nix-shell` to
fetch them.
- When ran manually, [./rebpf/build-loader.sh] builds the eBPF program in
`./build/` and generates compile_commands.json.
- Run `./build/bpf-load` to quickly load the eBPF program and check whether the
verifier accepts it.
- The nix package requires `./Cargo.nix` to be kept in sync with `Cargo.lock`
using [crate2nix], see [./scripts/update.sh].
- Build with `--features=bpf-trace` to enable debug output in
`/sys/kernel/debug/tracing/trace_pipe`.

[./shell.nix]: ./shell.nix
[./rebpf/build-loader.sh]: ./rebpf/build-loader.sh
[crate2nix]: https://github.com/nix-community/crate2nix
[./scripts/update.sh]: ./scripts/update.sh

## License

This project is released under the [GPLv3].

Rebpf icons are based on "Arrow Split" from Google's [Material icons] licensed under [Apache 2.0].

[GPLv3]: ./LICENSE.
[Material icons]: https://fonts.google.com/icons
[Apache 2.0]: https://www.apache.org/licenses/LICENSE-2.0.html
