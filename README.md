# **PensieveBPF**

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)


## **Getting Started**

To get started, simply click the "Use this template" button on the GitHub repository page. This will create
a new repository in your account with the same files and structure as this template.

### Use Nix

Using [direnv](https://github.com/direnv/direnv) and nix, you can quickly access a dev shell with a complete development environment.

With direnv, you can automatically load the required dependencies when you enter the directory.
This way you don't have to worry about installing dependencies to break your other project development environment.

See how to install direnv and Nix:
- direnv: https://github.com/direnv/direnv/blob/master/docs/installation.md
- Nix: run
```
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Then use the following command to enable direnv support in this directory.

```sh
direnv allow
```

If you want use nix flake without direnv, simply run:

```sh
nix develop
```

## **Features**

This starter template includes the following features:

- A **`Makefile`** that allows you to build the project in one command
- A **`Dockerfile`** to create a containerized environment for your project
- A **`flake.nix`** to enter a dev shell with needed dependencies
- A GitHub action to automate your build and publish process
  and docker image
- All necessary dependencies for C development with libbpf

## **How to use**

### **1. Clone your new repository**

Clone your newly created repository to your local machine:

```sh
git clone https://github.com/theodegeest/pensieveBPF.git --recursive
```

Or after clone the repo, you can update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **2. Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **3. Build the project**

To build the project, run the following command:

```sh
make -j
```

This will compile your code and create the necessary binaries. You can use the `Github Code space` or `Github Action` to build the project as well.

### ***Run the Project***

You can run the binary with:

```console
sudo ./src/pensieve
```

## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
