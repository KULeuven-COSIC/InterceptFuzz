#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Default target
TARGET="all"

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build the InterceptFuzz Docker images."
    echo "Note: The 'interceptfuzz-base' image is ALWAYS built first."
    echo ""
    echo "Options:"
    echo "  -t, --target   Target to build after base: 'ns-3-dev', 'openthread', 'none', or 'all' (default: all)"
    echo "  -h, --help     Show this help message and exit"
    echo ""
    echo "Examples:"
    echo "  $0 -t ns-3-dev"
    echo "  $0 -t openthread"
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -t|--target) 
            TARGET="${2,,}" # Convert to lowercase
            shift 2 
            ;;
        -h|--help) 
            show_help
            exit 0 
            ;;
        *) 
            echo "Error: Unknown parameter passed: $1"
            show_help
            exit 1 
            ;;
    esac
done

if [[ ! -f third_party/butterfly/Cargo.toml ]]; then
    echo "Error: third_party/butterfly is empty. Run: git submodule update --init"
    exit 1
fi

# Build functions
build_base() {
    echo "========================================"
    echo "[*] Building base image..."
    echo "========================================"
    docker build -t interceptfuzz-base .
}

build_ns3() {
    echo "========================================"
    echo "[*] Building ns-3-dev target image..."
    echo "========================================"
    docker build -t interceptfuzz-ns-3-dev ./targets/ns-3-dev
}

build_openthread() {
    echo "========================================"
    echo "[*] Building openthread target image..."
    echo "========================================"
    docker build -t interceptfuzz-openthread ./targets/openthread
}

# 1. ALWAYS build the base image first
build_base

# 2. Execute based on target selection
case "$TARGET" in
    ns-3-dev|ns3)
        build_ns3
        ;;
    openthread|ot)
        build_openthread
        ;;
    all)
        build_ns3
        build_openthread
        ;;
    none|base)
        echo "[*] Target set to '$TARGET'. Skipping secondary target builds."
        ;;
    *)
        echo "Error: Unknown target '$TARGET'."
        echo "Supported targets: ns-3-dev, openthread, none, all"
        exit 1
        ;;
esac

echo ""
echo "[+] Done!"