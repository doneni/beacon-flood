#include "main.h"
using namespace std;

#pragma pack(push, 1)
struct BeaconPacket final
{
    struct _ieee80211_radiotap_header radiotap_;
    struct _ieee80211_beacon_frame_header beacon_;
    struct _ieee80211_wireless_management_header wireless_;
};
#pragma pack(pop)

void usage()
{
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[])
{
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

long getCurrentTime()
{
    struct timespec currentTime;
    clock_gettime(CLOCK_REALTIME, &currentTime);
    struct timespec epoch = {0};
    time_t epochSeconds = mktime(gmtime(&epoch.tv_sec));
    time_t currentSeconds = mktime(gmtime(&currentTime.tv_sec));
    long timestampDifference = (currentSeconds - epochSeconds) * 1000000L + (currentTime.tv_nsec - epoch.tv_nsec) / 1000L;

    return timestampDifference;
}

int main(int argc, char** argv)
{
    if (!parse(&param, argc, argv))
		return -1;
    
    vector<string> ssid_list;
    ifstream openFile(argv[2]);
    if(openFile.is_open())
    {
        string line;
        while(getline(openFile, line))
            ssid_list.push_back(line);
        openFile.close();
    }

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
    }

    int i = 0;
    while(1)
    {
        struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}  

        struct _ieee80211_radiotap_header* radiotap_hdr = (struct _ieee80211_radiotap_header*)packet;
		struct _ieee80211_beacon_frame_header* beacon_hdr = (struct _ieee80211_beacon_frame_header*)(radiotap_hdr->it_len + packet);
		struct _ieee80211_wireless_management_header* wireless_hdr = (struct _ieee80211_wireless_management_header*)(radiotap_hdr->it_len + sizeof(_ieee80211_beacon_frame_header) + packet);

		if(beacon_hdr->frame_control != 0x80)
			continue;

        struct BeaconPacket modifiedPacket;
        memcpy(&modifiedPacket.radiotap_, packet, sizeof(struct _ieee80211_radiotap_header));
        packet += sizeof(struct _ieee80211_radiotap_header);
        memcpy(&modifiedPacket.beacon_, packet, sizeof(struct _ieee80211_beacon_frame_header));

        if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&modifiedPacket), sizeof(modifiedPacket)) != 0) {
            fprintf(stderr, "pcap_sendpacket failed - %s\n", pcap_geterr(pcap));
            break;
        }
        printf("modified beacon packet sent\n");
    }

    return 0;
}