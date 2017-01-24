#!/usr/bin/python

# Imports
import os, sys, getopt, struct

# Useful Defines
OTA_UPG_FILE_ID = 0x0beef11e
OTA_UPG_HDR_VER = 0x0100
OTA_UPG_HDR_MIN_HDR_LEN = 0x0038
OTA_UPG_HDR_FIELD_CTRL_SECURITY_CREDENTIAL_VER = 0x0001
OTA_UPG_HDR_FIELD_CTRL_DEVICE_SPECIFIC = 0x0002
OTA_UPG_HDR_FIELD_CTRL_HARDWARE_VER = 0x0004
OTA_UPG_HDR_FIELD_CTRL_MASK = (OTA_UPG_HDR_FIELD_CTRL_SECURITY_CREDENTIAL_VER | OTA_UPG_HDR_FIELD_CTRL_DEVICE_SPECIFIC | OTA_UPG_HDR_FIELD_CTRL_HARDWARE_VER)
OTA_UPG_HDR_ZIGBEE_STACK_2006 = 0x0000
OTA_UPG_HDR_ZIGBEE_STACK_2007 = 0x0001
OTA_UPG_HDR_ZIGBEE_STACK_PRO = 0x0002
OTA_UPG_HDR_ZIGBEE_STACK_IP = 0x0003
OTA_UPG_HDR_SEC_CRED_VER_SE_1_0 = 0x00
OTA_UPG_HDR_SEC_CRED_VER_SE_1_1 = 0x01
OTA_UPG_HDR_SEC_CRED_VER_SE_2_0 = 0x02
OTA_UPG_TAG_ID_UPG_IMG = 0x0000
OTA_UPG_TAG_ID_ECDSA_SIG = 0x0001
OTA_UPG_TAG_ID_ECDSA_SIGN_CERT = 0x0002

# Helper Functions
def usage():
    """Prints out usage info."""
    print "\nWraps a file in a ZigBee OTA Upgrade image header."
    print "NB: Very basic, assumes ZigBee Pro stack, doesn't allow for optional header fields, assumes a single upgrade image sub-element"
    print "\nUsage:"
    print "\t$ %s -f <file-to-wrap> -m <manufacturer-code> -i <image-type> -v <version> [-d <description>]" % (sys.argv[0])
    print "\nWhere:"
    print "\t-f, --file"
    print "\t\tThe path to the file to wrap"
    print "\t-m, --manufacturer-code"
    print "\t\tThe 16-bit hex ZigBee assigned manufacturer code"
    print "\t-i, --image-type"
    print "\t\tThe 16-bit hex image type"
    print "\t-v, --version"
    print "\t\tThe 32-bit hex image version"
    print "\t-d, --description"
    print "\t\tASCII string describing the upgrade image (optional, cut-off at 32 characters)"
    print "\t-h, --help"
    print "\t\tShows this usage info"

# Main function
def main():
    # Set-up options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:m:i:v:d:", ["help","file=","manufacturer-code=","image-type=","version=","description="])
    except getopt.GetoptError, e:
        sys.stderr.write(str(e))
        usage()
        sys.exit(1)

    # Default options
    filepath = None
    outfile = None
    mfg_code = None
    img_type = None
    version = None
    stack = None
    description = None

    # Process options
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0) 
        elif o in ("-f", "--file"):
            filepath = a
        elif o in ("-m", "--manufacturer-code"):
            mfg_code = int(a, 16)
        elif o in ("-i", "--image-type"):
            img_type = int(a, 16)
        elif o in ("-v", "--version"):
            version = int(a, 16)
        elif o in ("-d", "--description"):
            description = a
        else:
            usage()
            sys.exit(1)

    if (filepath is None) or (mfg_code is None) or (img_type is None) or (version is None):
        usage()
        sys.exit(1)
    if (description is None):
        description = ""

    if (mfg_code > 0xffff):
        print "Manufacturer Code must be a 16-bit hex value"
        sys.exit(1)
    if (img_type > 0xffff):
        print "Image Type must be a 16-bit hex value"
        sys.exit(1)
    if (version > 0xffffffff):
        print "Version must be a 32-bit hex value"
        sys.exit(1)
    if (len(description) > 32):
        print "Description string will be cut-off at 32 characters"

    # Open file
    with open(filepath, "rb") as myfile:
        # stat the file and squirrel away the size for later
        filestat = os.stat(filepath)
        filestat_size = filestat.st_size

        stack = OTA_UPG_HDR_ZIGBEE_STACK_PRO
        field_ctrl = 0
        total_img_sz = filestat_size + OTA_UPG_HDR_MIN_HDR_LEN + 6
        outfile = "/tmp/%04x-%04x-%08x.zigbee" % (mfg_code, img_type, version)
        print "Creating '%s'" % outfile
        with open(outfile, "wb+") as outf:
            ota_hdr = struct.pack("<IHHHHHIH32sI", OTA_UPG_FILE_ID, OTA_UPG_HDR_VER, OTA_UPG_HDR_MIN_HDR_LEN, field_ctrl, mfg_code, img_type, version, stack, description, total_img_sz)
            outf.write(ota_hdr)
            sub_elem_upg_img = struct.pack("<HI", 0, filestat_size)
            outf.write(sub_elem_upg_img)
            img = myfile.read()
            outf.write(img)

if __name__ == "__main__":
    main()
