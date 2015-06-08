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


    mdns_header(unsigned short flags, unsigned short qdcount = 0, unsigned short ancount = 0) {
        std::fill(rep_, rep_ + sizeof(rep_), 0);
        mdns_header::flags(flags);
        mdns_header::qdcount(qdcount);
        mdns_header::ancount(ancount);
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
//        for (size_t i = 0; i < HEADER_LENGTH; ++i) {
//            os << (int) header.rep_[i] << " ";
//        }
//        return os;
        return os.write(reinterpret_cast<const char *>(header.rep_), HEADER_LENGTH);
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
        string s = mdns_domain::readString(is);
        while (s.size()) {
            domain.parts.push_back(s);
            s = mdns_domain::readString(is);
        }
        return is;
    }

    static void writeString(std::ostream &os, string s) {
        os << "." << s;
    }

    friend std::ostream &operator<<(std::ostream &os, const mdns_domain &domain) {
//        for (int i = 0; i < domain.parts.size(); ++i) {
//            mdns_domain::writeString(os, domain.parts[i]);
//        }
//        return os;
        os.write(reinterpret_cast<char *>(domain.getData().data()), domain.getLength());
        return os;
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
        base.setQclass(be16toh(qtype_[0]));
        base.setReplyType(be16toh(qtype_[0]));
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_query_base &base) {
//        if (base.getQtype() == mdns_query_base::QTYPE_A) {
//            os << ":A";
//        } else if (base.getQtype() == mdns_query_base::QTYPE_PTR) {
//            os << ":PTR";
//        } else if (base.getQtype() == mdns_query_base::QTYPE_SRV) {
//            os << ":SRV";
//        } else if (base.getQtype() == mdns_query_base::QTYPE_ALL) {
//            os << ":ALL";
//        } else {
//            os << ":" << base.getQtype();
//        }
//        return os << ":" << base.getQclass() << ":" << (int) base.getReplyType();
        unsigned short qtype[1] = {htobe16(base.qtype)};
        unsigned short qclass[1] = {htobe16(base.qclass)};
        os.write((const char *) qtype, 2);
        os.write((const char *) qclass, 2);
        return os;
    }

    enum {
        LAST_15 = 0x7FFF,
        FIRST_1 = 0x8000
    };

    enum {
        QCLASS_INTERNET = 0x0001,
        QCLASS_ANY = 0x00FF,
        QTYPE_A = 0x0001,
        QTYPE_PTR = 0x000c,
        QTYPE_SRV = 0x0021,
        QTYPE_ALL = 0x00FF
    };

    mdns_query_base(unsigned short qtype, unsigned short qclass = 0) : qclass(qclass), qtype(qtype) { }

    mdns_query_base() { }

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
        is.get((char *) reply.rdata.data(), reply.getRdlength() + 1);
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, mdns_reply &reply) {
        mdns_query &query(reply);
//        os << "reply: " << query;
//        os << " ttl=" << reply.getTtl();
//        os << " rdlength=" << reply.getRdlength();
//        os << " rdata=";
//        if (reply.getQtype() == QTYPE_A) {
//            for (int i = 0; i < reply.getRdata().size(); ++i) {
//                if (i)os << ".";
//                os << (int) reply.getRdata()[i];
//            }
//        } else {
//            if (reply.getQtype() == QTYPE_PTR) {
//                os << "host_name:";
//                for (auto c:reply.getRdata()) {
//                    os.put(c);
//                }
//            } else {
//                for (auto c:reply.getRdata()) {
//                    os.put(c);
//                }
//            }
//        }
//        return os;
        os << query;
        unsigned int ttl[1] = {htobe32(reply.ttl)};
        os.write((const char *) ttl, 4);
        unsigned short rdlength[1] = {htobe16(reply.rdlength)};
        os.write((const char *) rdlength, 2);
        os.write(reinterpret_cast<char *>(reply.rdata.data()), reply.rdlength);
        return os;
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

    mdns_reply() : mdns_query() { }

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
