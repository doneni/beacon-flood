#include "main.h"
using namespace std;

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

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
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

    
    

    return 0;
}