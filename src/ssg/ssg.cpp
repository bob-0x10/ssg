#include <iostream>
#include "gssg.h"

void usage() {
	printf("syntax: ssg <interface> <filter>\n");
	printf("sample: ssg mon0 \"ether host 00:00:00:11:11:11\"\n");
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return -1;
	}
	std::string interface = std::string(argv[1]);
	std::string filter = "";
	if (argc == 3) filter = std::string(argv[2]);

	Ssg ssg(interface, filter);
	ssg.open();

	while (true) {
		int64_t adjustOffset = 0;
		std::cin >> adjustOffset;
		if (adjustOffset == 0) break;
		adjustOffset *= 1000000;
		ssg.apMap_.mutex_.lock();
		for (Ssg::ApMap::iterator it = ssg.apMap_.begin(); it != ssg.apMap_.end(); it++) {
			Ssg::ApInfo& apInfo = it->second;
			apInfo.adjustOffset(Diff(adjustOffset));
		}
		ssg.apMap_.mutex_.unlock();
	}

	ssg.close();
}
