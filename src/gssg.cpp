#include "gssg.h"

bool Ssg::BeaconFrame::init(BeaconHdr* beaconHdr, uint32_t size) {
	if (size > DummySize) {
		GTRACE("Too big beacon frame size(%d)\n", size);
		return false;
	}
	radiotapHdr_.len_ = sizeof(RadiotapHdr);
	radiotapHdr_.pad_ = 0;
	radiotapHdr_.ver_ = 0;
	radiotapHdr_.present_ = 0;
	memcpy((void*)&beaconHdr_, (void*)beaconHdr, size);
	size_ = size;
	return true;
}

void Ssg::BeaconFrame::send(pcap_t* handle) {
	int res = pcap_sendpacket(handle, (const u_char*)&radiotapHdr_, size_);
	if (res != 0) {
		GTRACE("pacp_sendpacket return %d - %s handle=%p size_=%u\n", res, pcap_geterr(handle), handle, size_);
	}
}

void Ssg::ApInfo::adjust(Diff offset, Diff interval) {
	adjustOffset_ = offset;
	adjustInterval_ = interval;
}


bool Ssg::open() {
	if (active_) return false;

	scanThread_ = new std::thread(_scanThread, this);
	sendThread_ = new std::thread(_sendThread, this);

	active_ = true;
	return true;
}

bool Ssg::close() {
	if (!active_) return false;
	active_ = false;

	scanThread_->join();
	delete scanThread_;
	scanThread_ = nullptr;

	sendThread_->join();
	delete sendThread_;
	sendThread_ = nullptr;

	return true;
}

void Ssg::_scanThread(Ssg* ssg) {
	ssg->scanThread();
}

void Ssg::scanThread() {
	GTRACE("scanThread beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface_.c_str(), errbuf);
		return;
	}

	while (active_) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		uint32_t size = header->caplen;
		RadiotapHdr* radiotapHdr = RadiotapHdr::check(pchar(packet), size);
		if (radiotapHdr == nullptr) continue;
		le16_t rlen = radiotapHdr->len_;
		if (rlen == _config.rt_.ignore_) continue;
		size -= radiotapHdr->len_;

		Dot11Hdr* dot11Hdr = Dot11Hdr::check(radiotapHdr, size);
		if (dot11Hdr == nullptr) continue;

		//
		// QosNull check
		//
		le8_t typeSubtype = dot11Hdr->typeSubtype();
		if (typeSubtype == Dot11Hdr::QosNull) {
			QosNullHdr* qosNullHdr = QosNullHdr::check(dot11Hdr, size);
			if (qosNullHdr == nullptr) continue;
			processQosNull(qosNullHdr);
			continue;
		}

		if (typeSubtype != Dot11Hdr::Beacon) continue;
		BeaconHdr* beaconHdr = BeaconHdr::check(dot11Hdr, size);
		if (beaconHdr == nullptr) continue;
		Mac bssid = beaconHdr->bssid();

		BeaconHdr::TrafficIndicationMap* tim = beaconHdr->getTim(size);
		if (tim == nullptr) continue;

		{
			std::lock_guard<std::mutex> guard(apMap_.mutex_);
			ApMap::iterator it = apMap_.find(bssid);

			if (it != apMap_.end()) {
				ApInfo apInfo;
				if (!apInfo.beaconFrame_.init(beaconHdr, size)) continue;
				apMap_.insert({bssid, apInfo});
				it = apMap_.find(bssid);
				assert(it != apMap_.end());
			}
			ApInfo& apInfo = it->second;
			SeqInfo seqInfo;
			seqInfo.ok_ = true;
			seqInfo.tv_ = header->ts;
			seqInfo.rlen_ = rlen;
			seqInfo.control_ = tim->control_;
			seqInfo.bitmap_ = tim->bitmap_;
			processAdjust(apInfo, beaconHdr->seq_, seqInfo);

		}
	}
	GTRACE("scanThread end\n");
}

void Ssg::_sendThread(Ssg* ssg) {
	ssg->sendThread();
}

void Ssg::sendThread() {
	GTRACE("sendThread beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface_.c_str(), 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface_.c_str(), errbuf);
		return;
	}

	while (active_) {
		for (ApMap::iterator it = apMap_.begin(); it != apMap_.end(); it++) {

		}
	}

	const u_char* p = (const u_char*)&ss;
	BeaconHdr* beaconHdr = PBeaconHdr(p + sizeof(RadiotapHdr));
	Diff interval = Diff(beaconHdr->fix_.beaconInterval_ * 1023995);
	//interval = Diff(5000000000); // 5 sec // gilgil temp 2020.11.01
	GTRACE("interval=%ld\n", interval.count());

	//std::this_thread::sleep_for(interval);
	Clock next= Timer::now();
	while (true) {
		Clock now = Timer::now();
		if (adjust != Diff(0)) {
			next += adjust;
			adjust = Diff(0);
		}
		if (now < next) {
			// continue; // gilgil temp 2020.11.04
			Diff remain = next - now;
			remain /= 2;
			remain -= Diff(20000000); // 20 millisecond
			//GTRACE("remain=%ld\n", remain.count());
			if (remain.count() > 0)
				std::this_thread::sleep_for(remain);
			continue;
		}
		beaconHdr->seq_ += 1;
		for (int i = 0; i < 1; i++) {
			//GTRACE("sending seq=%u\n", beaconHdr->seq_); // gilgil temp
			int res = pcap_sendpacket(handle, p, writeLen);
			if (res != 0) {
				GTRACE("pacp_sendpacket return %d - %s handle=%p writeLen=%u\n", res, pcap_geterr(handle), handle, writeLen);
				exit(-1);
			}
		}
		next += interval;
	}
	GTRACE("sendThread end\n");
}

void Ssg::processQosNull(QosNullHdr* qosNullHdr) {
	apMap_.mutex_.lock();
	Mac bssid = qosNullHdr->bssid();
	if (apMap_.find(bssid) != apMap_.end()) {
		printf("                                                                 QosNull bssid=%s sta=%s\n",
			std::string(qosNullHdr->bssid()).c_str(),
			std::string(qosNullHdr->sta()).c_str());
	}
	apMap_.mutex_.unlock();
}

void Ssg::processAdjust(ApInfo& apInfo, le16_t seq, SeqInfo seqInfo) {
	SeqMap& seqMap = apInfo.seqMap_;
	SeqMap::iterator it = seqMap.find(seq);
	if (it == seqMap.end()) {
		SeqInfos seqInfos;
		seqMap.insert({seq, seqInfos});
		it = seqMap.end();
		assert(it != seqMap.end());
	}
	SeqInfos& seqInfos = it->second;

	bool myPacket = seqInfo.control_ == _config.tim_.control_ && seqInfo.bitmap_ == _config.tim_.bitmap_;
	if (myPacket) {
		seqInfos.myInfo_ = seqInfo;
	} else {
		seqInfos.realInfo_ = seqInfo;
	}
	if (seqInfos.myInfo_.ok_ && seqInfos.realInfo_.ok_) {
		seqInfos.diffTime_ = getDiffTime(seqInfos.myInfo_.tv_, seqInfos.realInfo_.tv_);
		if (seqInfos.diffTime_ > _config.tooOldSeqCompareInterval_) { // real is too old
			seqInfos.realInfo_.clear();
			return;
		}
		if (seqInfos.diffTime_ < -_config.tooOldSeqCompareInterval_) { // my is too old
			seqInfos.myInfo_.clear();
			return;
		}
		seqMap.okCount_++;
	}
	if (seqMap.okCount_ >= _config.beaconAdjustCount_) {
		uint64_t offset = seqInfos.diffTime_;

		uint64_t interval(0);
		SeqMap::iterator prev = seqMap.begin();
		SeqMap::iterator next = prev; next++;
		assert(next != seqMap.end());
		int okCount = 0;
		while (true) {
			SeqInfo& prevSeqInfo = prev->second.realInfo_;
			SeqInfo& nextSeqInfo = next->second.realInfo_;
			if (prevSeqInfo.ok_ && nextSeqInfo.ok_) {
				uint64_t diff = getDiffTime(nextSeqInfo.tv_, prevSeqInfo.tv_);
				interval += diff;
				okCount++;
			}
			prev = next;
			if (++next == seqMap.end()) break;
		}
		interval /= okCount;
		apInfo.adjust(Diff(offset), Diff(interval));
		printf("offset=%ld interval=%ld\n", offset, interval);
		seqMap.clear();
		seqMap.okCount_ = 0;
	}
}

int64_t Ssg::getDiffTime(timeval tv1, timeval tv2) {
	int64_t res = (tv1.tv_sec - tv2.tv_sec) * 1000000;
	res += (tv1.tv_usec - tv2.tv_usec);
	return res;
}

