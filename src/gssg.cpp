#include "gssg.h"

void Ssg::ApInfo::adjust(Diff offset, Diff interval) {
	adjustOffset_ = offset;
	this->adjustInterval_ = interval;
}

Diff Ssg::ApMap::getMinNextTime() {
	return Diff(0);
};

bool Ssg::open(std::string devName) {
	(void)devName;
	return true;
}

bool Ssg::close() {
	return true;
}
