#!/bin/bash
CURRENT_KERNEL=`uname -r`
CURRENT_KERNEL_IMG_EXTRA="linux-image-extra-${CURRENT_KERNEL}"
CURRENT_KERNEL_IMG="linux-image-${CURRENT_KERNEL}"
CURRENT_KERNEL_HDR="linux-headers-${CURRENT_KERNEL}"

echo "Current Kernel:"
echo "${CURRENT_KERNEL}"
echo ""

INSTALLED_KERNEL_EXTRAS=`dpkg -l | grep -E 'linux-image-extra-[0-9]+' | grep ii | awk '{print $2}'`
INSTALLED_KERNELS=`dpkg -l | grep -E 'linux-image-[0-9]+' | grep ii | awk '{print $2}'`
INSTALLED_HEADERS=`dpkg -l | grep -E 'linux-headers-[0-9]+' | grep ii | awk '{print $2}'`

echo "Installed Kernel Extras:"
echo "${INSTALLED_KERNEL_EXTRAS}"
echo ""
echo "Installed Kernels:"
echo "${INSTALLED_KERNELS}"
echo ""
echo "Installed Headers:"
echo "${INSTALLED_HEADERS}"
echo ""

OIFS="$IFS"
IFS=$'\n'
INSTALLED_KERNEL_EXTRAS=( $INSTALLED_KERNEL_EXTRAS )
INSTALLED_KERNELS=( $INSTALLED_KERNELS )
INSTALLED_HEADERS=( $INSTALLED_HEADERS )
IFS="$OIFS"

for k in "${INSTALLED_KERNEL_EXTRAS[@]}"; do
    case "${k}" in
        linux-headers-generic)
            echo "Skipping meta-package: ${k}"
            ;;
        $CURRENT_KERNEL_IMG_EXTRA)
            echo "Keeping current kernel extras: ${k}"
            ;;
        *)
            echo "Remove old kernel extras: ${k}"
            sudo dpkg --remove $k
            ;;
    esac
done

for k in "${INSTALLED_KERNELS[@]}"; do
    case "${k}" in
        linux-image-generic)
            echo "Skipping meta-package: ${k}"
            ;;
        $CURRENT_KERNEL_IMG)
            echo "Keeping current kernel: ${k}"
            ;;
        *)
            echo "Remove old kernel: ${k}"
            sudo dpkg --remove $k
            ;;
    esac
done

for k in "${INSTALLED_HEADERS[@]}"; do
    case "${k}" in
        linux-headers-generic)
            echo "Skipping meta-package: ${k}"
            ;;
        $CURRENT_KERNEL_HDR)
            echo "Keeping current kernel headers: ${k}"
            ;;
        *)
            echo "Remove old kernel headers: ${k}"
            sudo dpkg --remove $k
            ;;
    esac
done

sudo apt-get autoremove

# If you accidentally remove the wrong kernel, this should fix things:
# sudo echo "linux-image-extra-3.13.0-74-generic install" | sudo dpkg --set-selections

