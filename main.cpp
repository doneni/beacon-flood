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

    for(auto& entry : ssid_list) 
        cout << entry << endl;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
    }

    struct BeaconPacket packet;

    return 0;
}