#!/bin/bash

HOME=$(pwd)
KERNEL_SRC="$HOME/linux"
LLVM_SRC="$HOME/llvm-project"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

install_llvm() {
    echo -e "${BLUE}==> Installing LLVM...${NC}"

    if [ -d "$LLVM_SRC" ]; then
        echo -e "${YELLOW}LLVM project already exists, skipping LLVM installation...${NC}"
    else
        git clone -b release/14.x https://github.com/llvm/llvm-project.git
        cd $LLVM_SRC
        echo -e "${YELLOW}Applying patch...${NC}"
        cp $HOME/tools/llvm-caplog.patch .
        git apply llvm-caplog.patch

        echo -e "${GREEN}Configuring LLVM...${NC}"
        cmake -S llvm -B build -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;lld"
    fi

    cd $HOME/llvm-project/build
    echo -e "${GREEN}Building LLVM...${NC}"
    make && sudo make install

    echo -e "${GREEN}LLVM installation completed!${NC}"
}

build_linux() {
    echo -e "${BLUE}==> Building Linux kernel...${NC}"
    cd $HOME

    if [ -d "$KERNEL_SRC" ]; then
        echo -e "${YELLOW}Linux kernel source already exists, skipping download...${NC}"
    else
        echo -e "${YELLOW}Downloading Linux kernel source...${NC}"
        wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.67.tar.xz
        tar -xf linux-6.6.67.tar.xz
        mv linux-6.6.67 linux
    fi

    cd $KERNEL_SRC
    make menuconfig LLVM=1
    make LLVM=1 -j`nproc` 2> err
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Kernel build completed successfully!${NC}"
    else
        echo -e "${RED}Kernel build failed! Check the logs for details.${NC}"
        exit 1
    fi
}

install_llvm
build_linux
