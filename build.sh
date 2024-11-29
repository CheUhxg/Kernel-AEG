#!/bin/bash

HOME=$(pwd)

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

install_llvm() {
    echo -e "${BLUE}==> Installing LLVM...${NC}"
    cd $HOME
    git clone -b release/14.x https://github.com/llvm/llvm-project.git
    cd llvm-project
    echo -e "${YELLOW}Applying patch...${NC}"
    cp $HOME/llvm-caplog.patch .
    git apply llvm-caplog.patch

    echo -e "${GREEN}Building LLVM...${NC}"
    cmake -S llvm -B build -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS=clang
    cd build && make -j$(nproc) && sudo make install
    echo -e "${GREEN}LLVM installation completed!${NC}"
}

build_linux() {
    echo -e "${BLUE}==> Building Linux kernel...${NC}"
    cd $HOME/linux
    make LLVM=1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Kernel build completed successfully!${NC}"
    else
        echo -e "${RED}Kernel build failed! Check the logs for details.${NC}"
        exit 1
    fi
}

install_llvm
build_linux
