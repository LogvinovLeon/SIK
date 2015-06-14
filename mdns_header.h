//
// Created by root on 06.06.15.
//

#ifndef SIK_OPOZNIENIA_MDNS_HEADER_H
#define SIK_OPOZNIENIA_MDNS_HEADER_H

#include <istream>
#include <iostream>
#include <iomanip>
#include <ostream>
#include <algorithm>
#include <assert.h>
#include <memory.h>

using namespace std;
const unsigned int HEADER_LENGTH = 12;

class mdns_header {
public:
    enum {
        query = 0x0000,
        response_authoritative = 0x8400,
        response_non_authoritative = 0x8000
    };

    mdns_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

    mdns_header(unsigned char data[]) {
        memcpy(rep_, data, HEADER_LENGTH);
        check();
    }


    mdns_header(unsigned short flags_, unsigned short qdcount_ = 0, unsigned short ancount_ = 0) {
        std::fill(rep_, rep_ + sizeof(rep_), 0);
        flags(flags_);
        qdcount(qdcount_);
        ancount(ancount_);
    }

    void check() {
        if (id() != 0) {
            throw "id";
        }
        if (!(flags() == query || flags() == response_non_authoritative || flags() == response_authoritative)) {
            throw "flags";
        }
    }

    unsigned short id() const { return decode(0, 1); }

    unsigned short flags() const { return decode(2, 3); }

    unsigned short qdcount() const { return decode(4, 5); }

    unsigned short ancount() const { return decode(6, 7); }

    unsigned short nscount() const { return decode(8, 9); }

    unsigned short arcount() const { return decode(10, 11); }

    void id(unsigned short n) { encode(0, 1, n); }

    void flags(unsigned short n) { encode(2, 3, n); }

    void qdcount(unsigned short n) { encode(4, 5, n); }

    void ancount(unsigned short n) { encode(6, 7, n); }

    void nscount(unsigned short n) { encode(8, 9, n); }

    void arcount(unsigned short n) { encode(10, 11, n); }

    friend std::istream &operator>>(std::istream &is, mdns_header &header) {
        is.read(reinterpret_cast<char *>(header.rep_), HEADER_LENGTH);
        header.check();
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_header &header) {
        return os.write(reinterpret_cast<const char *>(header.rep_), HEADER_LENGTH);
    }

    string toString() {
        stringstream os;
        for (size_t i = 0; i < HEADER_LENGTH; ++i) {
            os << std::hex << (int) rep_[i] << " ";
        }
        return os.str();
    }

private:
    unsigned short decode(int a, int b) const {
        assert(a + 1 == b);
        return (rep_[a] << 8) + rep_[b];
    }

    void encode(int a, int b, unsigned short n) {
        assert(a + 1 == b);
        rep_[a] = static_cast<unsigned char>(n >> 8);
        rep_[b] = static_cast<unsigned char>(n & 0xFF);
    }

    unsigned char rep_[HEADER_LENGTH];
};

class mdns_domain {
public:
    bool operator<(const mdns_domain &d) const {
        return this->parts < d.getParts();
    }

    static string readString(std::istream &is) {
        string s;
        unsigned char len[1];
        is.get((char *) len, 2);
        for (auto i = 0; i < len[0]; ++i) {
            char c;
            is.get(c);
            s += c;
        }
        return s;
    }

    friend std::istream &operator>>(std::istream &is, mdns_domain &domain) {
        domain.parts.clear();
        string s = readString(is);
        while (s.size()) {
            domain.parts.push_back(s);
            s = readString(is);
        }
        return is;
    }

    static void writeString(std::ostream &os, string s) {
        os << "." << s;
    }

    friend std::ostream &operator<<(std::ostream &os, const mdns_domain &domain) {
        os.write(reinterpret_cast<char *>(domain.getData().data()), domain.getLength());
        return os;
    }

    string toString() {
        stringstream os;
        for (int i = 0; i < parts.size(); ++i) {
            mdns_domain::writeString(os, parts[i]);
        }
        return os.str();
    }

    string getName() const {
        return parts.at(parts.size() - 4);
    }

    string getType() const {
        return parts.at(parts.size() - 3);
    }

    string getProtocol() const {
        return parts.at(parts.size() - 2);
    }

    string getLocal() const {
        return parts.at(parts.size() - 1);
    }

    bool operator==(const std::initializer_list<string> &l) const {
        return parts == vector<string>(l);
    }

    mdns_domain() { }

    mdns_domain(const vector<string> &parts) : parts(parts) { }

    mdns_domain(const std::initializer_list<string> &parts) : parts(parts) { }

    mdns_domain(const vector<unsigned char> &data) {
        string str((const char *) data.data(), data.size());
        std::istringstream ss(str);
        ss >> *this;
    }

    const vector<string> &getParts() const {
        return parts;
    }

    void setParts(const vector<string> &parts) {
        mdns_domain::parts = parts;
    }

    unsigned short getLength() const {
        unsigned short sum = 1;
        for (const auto &part: parts) {
            sum = (unsigned short) (sum + part.size() + 1);
        }
        return sum;
    }

    vector<unsigned char> getData() const {
        vector<unsigned char> data;
        data.reserve(getLength());
        for (const auto &part: parts) {
            data.push_back((const unsigned char &) part.size());
            for (auto c:part)
                data.push_back((const unsigned char &) c);
        }
        data.push_back(0);
        assert(data.size() == getLength());
        return data;
    }

protected:
    vector<string> parts;
};

class mdns_query_base {
public:
    unsigned short getQtype() const {
        return qtype;
    }

    unsigned short getQclass() const {
        return (qclass & LAST_15);
    }

    unsigned char getReplyType() const {
        return (unsigned char) (qclass & FIRST_1);
    }


    void setQtype(unsigned short qtype) {
        mdns_query_base::qtype = qtype;
    }

    void setQclass(unsigned short qclass) {
        mdns_query_base::qclass = ((mdns_query_base::qclass & FIRST_1) +
                                   (qclass & LAST_15));
    }

    void setReplyType(unsigned char reply_type) {
        mdns_query_base::qclass = ((mdns_query_base::qclass & LAST_15) +
                                   (reply_type & FIRST_1));
    }

    void check() {
        if (getQclass() != QCLASS_INTERNET && getQclass() != QCLASS_ANY) {
            throw "qclass";
        }
    }

    friend std::istream &operator>>(std::istream &is, mdns_query_base &base) {
        unsigned short qtype_[1];
        unsigned short qclass_[1];
        is.get((char *) qtype_, 3);
        is.get((char *) qclass_, 3);
        base.setQtype(be16toh(qtype_[0]));
        base.setQclass(be16toh(qclass_[0]));
        base.setReplyType(be16toh(qclass_[0]));
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_query_base &base) {
        unsigned short qtype[1] = {htobe16(base.qtype)};
        unsigned short qclass[1] = {htobe16(base.qclass)};
        os.write((const char *) qtype, 2);
        os.write((const char *) qclass, 2);
        return os;
    }

    virtual string toStringBase() {
        stringstream os;
        os << ":";
        if (getQtype() == mdns_query_base::QTYPE_A) {
            os << "A";
        } else if (getQtype() == mdns_query_base::QTYPE_PTR) {
            os << "PTR";
        } else if (getQtype() == mdns_query_base::QTYPE_SRV) {
            os << "SRV";
        } else if (getQtype() == mdns_query_base::QTYPE_ALL) {
            os << "ALL";
        } else if (getQtype() == mdns_query_base::QTYPE_TXT) {
            os << "TXT";
        } else {
            os << getQtype();
        }
        os << ":";
        if (getQclass() == mdns_query_base::QCLASS_INTERNET) {
            os << "INT";
        } else if (getQclass() == mdns_query_base::QCLASS_ANY) {
            os << "ANY";
        } else {
            os << getQclass();
        }
        os << ":" << (int) getReplyType();
        return os.str();
    }

    enum {
        LAST_15 = 0x7FFF,
        FIRST_1 = 0x8000
    };

    enum {
        QCLASS_INTERNET = 0x0001,
        QCLASS_ANY = 0x00FF,
        QTYPE_A = 0x0001,
        QTYPE_TXT = 0x0010,
        QTYPE_PTR = 0x000c,
        QTYPE_SRV = 0x0021,
        QTYPE_ALL = 0x00FF
    };

    mdns_query_base(unsigned short qtype = 0, unsigned short qclass = 0) : qclass(qclass), qtype(qtype) { }

protected:
    unsigned short qclass;
private:
    unsigned short qtype;
};

class mdns_query : public mdns_query_base {
public:
    friend std::istream &operator>>(std::istream &is, mdns_query &query) {
        is >> query.domain;
        mdns_query_base &base(query);
        is >> base;
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_query &query) {
        os << query.domain;
        mdns_query_base &base(query);
        return os << base;
    }

    string toString() {
        stringstream os;
        os << domain.toString();
        os << toStringBase();
        return os.str();
    }

    const mdns_domain &getDomain() const {
        return domain;
    }

    void setDomain(const mdns_domain &domain) {
        mdns_query::domain = domain;
    }


    mdns_query(const mdns_domain &domain, unsigned short qtype, unsigned short qclass = QCLASS_INTERNET)
            : mdns_query_base(qtype, qclass), domain(domain) { }

    mdns_query() : mdns_query_base() { }

protected:
    mdns_domain domain;
};

class mdns_reply : public mdns_query {
public:
    friend std::istream &operator>>(std::istream &is, mdns_reply &reply) {
        mdns_query &query(reply);
        is >> query;
        unsigned int ttl_[1];
        is.get((char *) ttl_, 5);
        reply.setTtl(be32toh(ttl_[0]));
        unsigned short rdlength_[1];
        is.get((char *) rdlength_, 3);
        reply.setRdlength(be16toh(rdlength_[0]));
        reply.rdata.resize(reply.getRdlength());
        is.get((char *) reply.rdata.data(), reply.getRdlength());
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_reply &reply) {
        mdns_query &query(reply);
        os << query;
        unsigned int ttl[1] = {htobe32(reply.ttl)};
        os.write((const char *) ttl, 4);
        unsigned short rdlength[1] = {htobe16(reply.rdlength)};
        os.write((const char *) rdlength, 2);
        os.write(reinterpret_cast<char *>(reply.rdata.data()), reply.rdlength);
        return os;
    }

    string toString() {
        mdns_query &query(*this);
        stringstream os;
        os << "reply: " << query.toString();
        os << " ttl=" << getTtl();
        os << " rdlength=" << getRdlength();
        os << " rdata=";
        if (getQtype() == QTYPE_A) {
            for (int i = 0; i < getRdata().size(); ++i) {
                if (i)os << ".";
                os << (int) getRdata()[i];
            }
        } else {
            if (getQtype() == QTYPE_PTR) {
                os << "host_name:";
                os << mdns_domain(getRdata());
            } else {
                for (auto c:getRdata()) {
                    os.put(c);
                }
            }
        }
        return os.str();
    }

    unsigned int getTtl() const {
        return ttl;
    }

    void setTtl(unsigned int ttl) {
        mdns_reply::ttl = ttl;
    }

    unsigned short getRdlength() const {
        return rdlength;
    }

    void setRdlength(unsigned short rdlength) {
        mdns_reply::rdlength = rdlength;
    }

    unsigned char getCacheFlush() const {
        return (unsigned char) (qclass & FIRST_1);
    }

    void setCacheFlush(unsigned char cache_flush) {
        mdns_query_base::qclass = (mdns_query_base::qclass & LAST_15) + (qclass & FIRST_1);
    }

    const vector<unsigned char> &getRdata() const {
        return rdata;
    }

    void setRdata(const vector<unsigned char> &rdata) {
        mdns_reply::rdata = rdata;
    }

    void setRdata(boost::asio::ip::address_v4::bytes_type data) {
        mdns_reply::rdata = vector<unsigned char>(data.begin(), data.end());
    }

    boost::asio::ip::address_v4 getIP() const {
        assert(getQtype() == QTYPE_A);
        unsigned long addr;
        memcpy(&addr, rdata.data(), 4);
        return (const boost::asio::ip::address_v4 &) addr;
    }

    mdns_domain getPTRData() const {
        return mdns_domain(this->rdata);
    }


    mdns_reply(const mdns_domain &domain, unsigned short qtype, unsigned int ttl,
               unsigned short rdlength, const vector<unsigned char> &rdata)
            : mdns_query(domain, qtype) {
        this->setTtl(ttl);
        this->setRdlength(rdlength);
        this->setRdata(rdata);
    }

    mdns_reply(const mdns_domain &domain, unsigned short qtype, unsigned int ttl,
               const mdns_domain &name)
            : mdns_query(domain, qtype) {
        this->setTtl(ttl);
        this->setRdlength(name.getLength());
        this->setRdata(name.getData());
    }

    mdns_reply(const mdns_domain &domain, unsigned short qtype, unsigned int ttl,
               const boost::asio::ip::address_v4 &ip)
            : mdns_query(domain, qtype) {
        this->setTtl(ttl);
        this->setRdlength(4);
        this->setRdata(ip.to_bytes());
    }

    mdns_reply() : mdns_query(), ttl(0), rdlength(0), rdata({}) { }

protected:
    unsigned int ttl;
    unsigned short rdlength;
    vector<unsigned char> rdata;
};

class mdns_package {
public:
    friend std::istream &operator>>(std::istream &is, mdns_package &package) {
        is >> package.header;
        for (int i = 0; i < package.header.qdcount(); ++i) {
            mdns_query query;
            is >> query;
            package.queries.push_back(query);
        }
        for (int i = 0; i < package.header.ancount(); ++i) {
            mdns_reply reply;
            is >> reply;
            package.replies.push_back(reply);
        }
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_package &package) {
        os << package.header;
        for (int i = 0; i < package.queries.size(); ++i)
            os << package.queries[i];
        for (int i = 0; i < package.replies.size(); ++i)
            os << package.replies[i];
        return os;
    }

    string toString() {
        stringstream os;
        os << header.toString();
        for (int i = 0; i < queries.size(); ++i) {
            os << queries[i].toString();
        }
        for (int i = 0; i < replies.size(); ++i) {
            os << replies[i].toString();
        }
        return os.str();
    }

    const mdns_header &getHeader() const {
        return header;
    }

    void setHeader(const mdns_header &header) {
        mdns_package::header = header;
    }

    const vector<mdns_query> &getQueries() const {
        return queries;
    }

    void setQueries(const vector<mdns_query> &queries) {
        mdns_package::queries = queries;
    }

    const vector<mdns_reply> &getReplies() const {
        return replies;
    }

    void setReplies(const vector<mdns_reply> &replies) {
        mdns_package::replies = replies;
    }

    void addQuery(const mdns_query &query) {
        queries.push_back(query);
        header.qdcount((unsigned short) (header.qdcount() + 1));
    }

    void addReply(const mdns_reply &reply) {
        replies.push_back(reply);
        header.ancount((unsigned short) (header.ancount() + 1));
    }

    mdns_package(const mdns_header &header, const vector<mdns_query> &queries, const vector<mdns_reply> &replies)
            : header(header), queries(queries), replies(replies) { }

    mdns_package(const mdns_header &header) : header(header) { }

    mdns_package() { }

private:
    mdns_header header;
    vector<mdns_query> queries;
    vector<mdns_reply> replies;
};


#endif //SIK_OPOZNIENIA_MDNS_HEADER_H
