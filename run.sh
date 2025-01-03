#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

HOME=$(pwd)
KERNEL_SRC="$HOME/linux"
IDENT_SRC="$HOME/identifier"

run_identifier() {
    echo -e "${BLUE}==> Running identifier tool...${NC}"
    mkdir dump
    $IDENT_SRC/build/lib/identifier -debug-verbose 0 -dump-keystructs -output-dir $HOME/dump/ `find ${KERNEL_SRC} -name "*\.bc"`
    echo -e "${GREEN}Identifier tool execution completed.${NC}"
}

run_trigger() {
    echo -e "${BLUE}==> Running trigger tool...${NC}"
    # TODO:
    echo -e "${GREEN}Trigger tool execution completed.${NC}"
}

show_help() {
    echo -e "${YELLOW}Usage: $0 <tool>${NC}"
    echo ""
    echo -e "${GREEN}Tools:${NC}"
    echo -e "  ${BLUE}identifier${NC}    Analyze the kernel source and identify specific objects."
    echo -e "  ${BLUE}trigger${NC}       Generate code to trigger specific kernel objects based on identifier output."
    exit 1
}

if [ $# -eq 0 ]; then
    echo -e "${RED}Error: No tool specified.${NC}"
    show_help
fi

case "$1" in
    identifier)
        run_identifier
        ;;
    trigger)
        run_trigger
        ;;
    *)
        echo -e "${RED}Error: Unknown tool '$1'.${NC}"
        show_help
        ;;
esac
