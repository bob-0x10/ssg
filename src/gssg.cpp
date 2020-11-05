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

void Ssg::ApInfo::adjustOffset(Diff adjustOffset) {
	adjustOffset_ = adjustOffset;
}

void Ssg::ApInfo::adjustInterval(Diff adjustInterval) {
	adjustInterval_ = adjustInterval;
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
		GTRACE("pcap_open_live(%s) return null - %s\n", interface_.c_str(), errbuf);
		return;
	}

	if (filter_ != "") {
		u_int uNetMask = 0xFFFFFFFF;;
		bpf_program code;

		if (pcap_compile(handle, &code, filter_.c_str(), 1, uNetMask) < 0) {
			GTRACE("error in pcap_compile(%s)\n", pcap_geterr(handle));
			pcap_close(handle);
			return;
		}
		if (pcap_setfilter(handle, &code) < 0) {
			GTRACE("error in pcap_setfilter(%s)\n", pcap_geterr(handle));
			pcap_close(handle);
			return;
		}
	}

	while (active_) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			GTRACE("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		uint32_t size = header->caplen;
		RadiotapHdr* radiotapHdr = RadiotapHdr::check(pchar(packet), size);
		if (radiotapHdr == nullptr) continue;
		le16_t rlen = radiotapHdr->len_;
		// ----- gilgil temp -----
		//GTRACE("radiotapHdr->len_=%u\n", rlen);
		//if (rlen == _config.rt_.mysending) {
		//	GTRACE("my sending\n");
		//}
		// -----------------------
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
			// processQosNull(qosNullHdr); // gilgil temp
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

			if (it == apMap_.end()) {
				tim->control_ = _config.tim_.control_;
				tim->bitmap_ = _config.tim_.bitmap_;
				ApInfo apInfo;
				if (!apInfo.beaconFrame_.init(beaconHdr, size)) continue;
				apInfo.sendInterval_ = Diff(beaconHdr->fix_.beaconInterval_ * 1024000);
				apInfo.nextFrameSent_ = Timer::now() + apInfo.sendInterval_;
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
	pcap_close(handle);
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
		GTRACE("pcap_open_live(%s) return null - %s\n", interface_.c_str(), errbuf);
		return;
	}

	while (active_) {
		Clock now = Timer::now();
		apMap_.mutex_.lock();
		for (ApMap::iterator it = apMap_.begin(); it != apMap_.end(); it++) {
			ApInfo& apInfo = it->second;
			if (apInfo.adjustOffset_ != Diff(0)) {
				apInfo.nextFrameSent_+= apInfo.adjustOffset_;
				apInfo.adjustOffset_ = Diff(0);
			}
			if (apInfo.adjustInterval_ != Diff(0)) {
				apInfo.sendInterval_ += apInfo.adjustInterval_;
				apInfo.adjustInterval_ = Diff(0);
				GTRACE("adjustInterval=%ld sendInterval=%ld\n", apInfo.adjustInterval_.count(), apInfo.sendInterval_.count());
			}
			if (now >= apInfo.nextFrameSent_) {
				le16_t seq = apInfo.beaconFrame_.beaconHdr_.seq_;
				seq++;
				apInfo.beaconFrame_.beaconHdr_.seq_ = seq++;

				apInfo.beaconFrame_.send(handle);
				// ----- gilgil temp -----
				//{
				//	std::string bssid = std::string(it->first);
				//	GTRACE("sending beacon %s seq=%d\n", bssid.c_str(), seq); // gilgil temp
				//	apInfo.nextFrameSent_ = now + apInfo.sendInterval_;
				//}
				// -----------------------
				apInfo.nextFrameSent_ += apInfo.sendInterval_;
			}
		}

		now = Timer::now();
		Diff minWaitTime = Diff(_config.sendPollingTime_ * 2);
		for (ApMap::iterator it = apMap_.begin(); it != apMap_.end(); it++) {
			ApInfo& apInfo = it->second;
			Diff diff = apInfo.nextFrameSent_ - now;
			if (minWaitTime < diff)
				minWaitTime = diff;
		}
		apMap_.mutex_.unlock();

		minWaitTime /= 2;
		minWaitTime -= Diff(_config.sendPollingTime_);
		if (minWaitTime > Diff(0))
			std::this_thread::sleep_for(minWaitTime);
	}
	pcap_close(handle);
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
		it = seqMap.find(seq);
		assert(it != seqMap.end());
	}
	SeqInfos& seqInfos = it->second;

	bool myPacket = seqInfo.control_ == _config.tim_.control_ && seqInfo.bitmap_ == _config.tim_.bitmap_;
	if (myPacket) {
		seqInfos.myInfo_ = seqInfo;
	} else {
		seqInfos.realInfo_ = seqInfo;
	}
	if (seqInfos.isOk()) {
		int64_t diffTime = getDiffTime(seqInfos.realInfo_.tv_, seqInfos.myInfo_.tv_);
		if (diffTime > _config.tooOldSeqCompareInterval_) { // my is too old
			GTRACE("i am too old %ld\n", diffTime);
			seqInfos.myInfo_.clear();
			return;
		}
		if (diffTime < -_config.tooOldSeqCompareInterval_) { // real is too old
			GTRACE("real is too old %ld\n", diffTime);
			seqInfos.realInfo_.clear();
			return;
		}
		seqMap.okCount_++;
	}
	if (seqMap.okCount_ >= _config.beaconAdjustCount_) {
		//
		// seq my   real
		// 100 1010 1000
		// 101 1019 1009
		// 102 1030 1018
		// 103 1040 1027
		//
		// adjustOffset = -13 : (1027- 1040)
		// adjustInterval = -1 : ((1027 - 1000) - (1040 - 1010)) / 3
		//
		timeval firstMyTv{0,0}, firstRealTv{0,0};
		for (SeqMap::iterator it = seqMap.begin(); it != seqMap.end(); it++) {
			SeqInfos& seqInfos = it->second;
			if (seqInfos.isOk()) {
				firstMyTv = seqInfos.myInfo_.tv_;
				firstRealTv = seqInfos.realInfo_.tv_;
				break;
			}
		}
		assert(!(firstMyTv.tv_sec == 0 && firstMyTv.tv_usec == 0));

		timeval lastMyTv{0,0}, lastRealTv{0,0};
		for (SeqMap::reverse_iterator it = seqMap.rbegin(); it != seqMap.rend(); it++) {
			SeqInfos& seqInfos = it->second;
			if (seqInfos.isOk()) {
				lastMyTv = seqInfos.myInfo_.tv_;
				lastRealTv = seqInfos.realInfo_.tv_;
				break;
			}
		}
		assert(!(lastMyTv.tv_sec == 0 && lastRealTv.tv_usec == 0));

		int64_t adjustOffset = getDiffTime(lastRealTv, lastMyTv);
		assert(seqMap.okCount_ > 1);
		int64_t realDiff = getDiffTime(lastRealTv, firstRealTv);
		int64_t myDiff = getDiffTime(lastMyTv, firstMyTv);
		int64_t adjustInterval = (realDiff - myDiff) / (seqMap.okCount_ - 1);
		apInfo.adjustOffset(Diff(adjustOffset));
		apInfo.adjustInterval(Diff(adjustInterval));
		GTRACE("realDiff=%ld myDiff=%ld adjustOffset=%ld adjustInterval=%ld\n", realDiff, myDiff, adjustOffset, adjustInterval);
		seqMap.clear();
	}
}

int64_t Ssg::getDiffTime(timeval tv1, timeval tv2) {
	int64_t res = (tv1.tv_sec - tv2.tv_sec) * 1000000;
	res += (tv1.tv_usec - tv2.tv_usec);
	return res;
}

