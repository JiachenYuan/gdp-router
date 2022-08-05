# gdp-router

## Developing Quickstart

First install [`Vagrant`](https://www.vagrantup.com/) and [`VirtualBox`](https://www.virtualbox.org/) on your system. Also install the following `Vagrant` plugins,

```
host$ vagrant plugin install vagrant-reload vagrant-disksize vagrant-vbguest
```

Then clone our sandbox repository, start and ssh into the Vagrant VM,

```
host$ git clone https://github.com/capsule-rs/sandbox.git
host$ cd sandbox
host$ vagrant up
host$ vagrant ssh
```

Clone the gdp-router repo into /gdp inside the VM:

```
vagrant$ git clone https://github.com/JiachenYuan/gdp-router.git /gdp/gdp-router
```

Run the sandbox with the command,

```
vagrant$ docker run -it --rm \
    --privileged \
    --network=host \
    --name sandbox \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -v /lib/modules:/lib/modules \
    -v /dev/hugepages:/dev/hugepages \
    -v /gdp:/gdp \
    -v/usr/local/cargo/registry:/usr/local/cargo/registry/
    getcapsule/sandbox:19.11.6-1.50 /bin/bash
```

Run the router,

```
vagrant$ cd /gdp
vagrant$ cargo run
```
