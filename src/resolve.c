#include "proxy.h"
#ifdef WITH_SSL
#ifdef WITH_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/x509v3.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif
#include "ssl.h"
#endif

struct nserver nservers[MAXNSERVERS];
struct nserver authnserver;

static int dnsqmatch(const unsigned char *a, const unsigned char *b, int len){
	int i;

	for(i = 0; i < len; i++){
		unsigned char c1 = a[i], c2 = b[i];

		if(c1 >= 'A' && c1 <= 'Z') c1 += 'a' - 'A';
		if(c2 >= 'A' && c2 <= 'Z') c2 += 'a' - 'A';
		if(c1 != c2) return 1;
	}
	return 0;
}

#ifdef WITH_SSL
static _3proxy_mutex_t dot_mutexes[MAXNSERVERS];
static _3proxy_mutex_t dot_auth_mutex;

/* Called once from main() before any service can resolve a name. Lazy
   initialization would race: DNS lookups run on several service threads. */
void dot_init_mutexes(void){
	int i;
	for(i = 0; i < MAXNSERVERS; i++){
		_3proxy_mutex_init(&dot_mutexes[i]);
		nservers[i].dot_sock = INVALID_SOCKET;
	}
	_3proxy_mutex_init(&dot_auth_mutex);
	authnserver.dot_sock = INVALID_SOCKET;
}

static _3proxy_mutex_t *dot_get_mutex(struct nserver *ns){
	int i;
	if(ns == &authnserver) return &dot_auth_mutex;
	for(i = 0; i < MAXNSERVERS; i++){
		if(ns == &nservers[i]) return &dot_mutexes[i];
	}
	return &dot_mutexes[0];
}

static int is_ip_literal(const char *s){
	struct in_addr a4;
	struct in6_addr a6;
	if(!s) return 0;
	if(inet_pton(AF_INET, s, &a4) == 1) return 1;
	if(inet_pton(AF_INET6, s, &a6) == 1) return 1;
	return 0;
}

static int dot_init_ctx(struct nserver *ns){
	char *ca_file;
	char *ca_dir;

	if(ns->dot_ctx) return 0;
	ssl_init();
#if !defined(WITH_WOLFSSL) && OPENSSL_VERSION_NUMBER < 0x10100000L
	ns->dot_ctx = (void *)SSL_CTX_new(SSLv23_client_method());
#else
	ns->dot_ctx = (void *)SSL_CTX_new(TLS_client_method());
#endif
	if(!ns->dot_ctx) return 1;

#if !defined(WITH_WOLFSSL) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	if(SSL_CTX_set_min_proto_version((SSL_CTX *)ns->dot_ctx, TLS1_2_VERSION) != 1){
		SSL_CTX_free((SSL_CTX *)ns->dot_ctx);
		ns->dot_ctx = NULL;
		return 1;
	}
#else
	SSL_CTX_set_options((SSL_CTX *)ns->dot_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif

	ca_file = ssl_get_client_ca_file();
	ca_dir = ssl_get_client_ca_dir();
	if(ca_file || ca_dir){
		if(SSL_CTX_load_verify_locations((SSL_CTX *)ns->dot_ctx, ca_file, ca_dir) != 1){
			fprintf(stderr, "3proxy DoT: failed to load CA file %s or dir %s\n",
				ca_file ? ca_file : "", ca_dir ? ca_dir : "");
			SSL_CTX_free((SSL_CTX *)ns->dot_ctx);
			ns->dot_ctx = NULL;
			return 1;
		}
	}
	else {
#ifdef _WIN32
		char *ca_store = ssl_get_client_ca_store();
		int loaded = 0;

		if(ca_store && *ca_store){
			/* An explicitly configured store is authoritative: never
			   silently widen trust to the default paths if it is empty. */
			loaded = ssl_load_windows_store((SSL_CTX *)ns->dot_ctx, ca_store);
			if(loaded == 0){
				fprintf(stderr, "3proxy DoT: failed to load CA store %s\n", ca_store);
				SSL_CTX_free((SSL_CTX *)ns->dot_ctx);
				ns->dot_ctx = NULL;
				return 1;
			}
		}
		else {
			loaded += ssl_load_windows_store((SSL_CTX *)ns->dot_ctx, "ROOT");
			loaded += ssl_load_windows_store((SSL_CTX *)ns->dot_ctx, "CA");
			loaded += ssl_load_windows_store((SSL_CTX *)ns->dot_ctx, "AuthRoot");
			if(loaded == 0){
				if(SSL_CTX_set_default_verify_paths((SSL_CTX *)ns->dot_ctx) != 1){
					fprintf(stderr, "3proxy DoT: failed to load default verify paths\n");
					SSL_CTX_free((SSL_CTX *)ns->dot_ctx);
					ns->dot_ctx = NULL;
					return 1;
				}
			}
		}
#else
		if(SSL_CTX_set_default_verify_paths((SSL_CTX *)ns->dot_ctx) != 1){
			fprintf(stderr, "3proxy DoT: failed to load system default verify paths\n");
			SSL_CTX_free((SSL_CTX *)ns->dot_ctx);
			ns->dot_ctx = NULL;
			return 1;
		}
#endif
	}
	SSL_CTX_set_verify((SSL_CTX *)ns->dot_ctx, SSL_VERIFY_PEER, NULL);
	return 0;
}

static void dot_close_conn(struct nserver *ns){
	if(ns->dot_ssl){
		SSL_shutdown((SSL *)ns->dot_ssl);
		SSL_free((SSL *)ns->dot_ssl);
		ns->dot_ssl = NULL;
	}
	if(ns->dot_sock != INVALID_SOCKET){
		so._shutdown(so.state, ns->dot_sock, SHUT_RDWR);
		so._closesocket(so.state, ns->dot_sock);
		ns->dot_sock = INVALID_SOCKET;
	}
}

static void dot_set_nonblock(SOCKET sock){
#ifdef _WIN32
	unsigned long ul = 1;
	ioctlsocket(sock, FIONBIO, &ul);
#else
	fcntl(sock, F_SETFL, O_NONBLOCK | fcntl(sock, F_GETFL));
#endif
}

static int dot_connect(struct nserver *ns){
	SOCKET sock;
	SSL *ssl;
	int err;
	long vres;
	X509 *cert;
	PROXYSOCKADDRTYPE sinsl;

	if(dot_init_ctx(ns)) return 1;

	memset(&sinsl, 0, sizeof(sinsl));
	*SAFAMILY(&sinsl) = *SAFAMILY(&ns->addr);

	if((sock = so._socket(so.state, SASOCK(&sinsl), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET){
		return 1;
	}
	if(so._bind(so.state, sock, (struct sockaddr *)&sinsl, SASIZE(&sinsl))){
		so._closesocket(so.state, sock);
		return 1;
	}
	if(connectwithpoll(NULL, sock, (struct sockaddr *)&ns->addr, SASIZE(&ns->addr), conf.timeouts[CONNECT_TO])){
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		return 1;
	}
	dot_set_nonblock(sock);
#ifdef TCP_NODELAY
	{
		int opt = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
	}
#endif

	ssl = SSL_new((SSL_CTX *)ns->dot_ctx);
	if(!ssl){
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		return 1;
	}
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_AUTO_RETRY);
	if(!SSL_set_fd(ssl, sock)){
		SSL_free(ssl);
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		return 1;
	}

	if(ns->hostname && *ns->hostname){
		X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
		if(!param){
			SSL_free(ssl);
			so._shutdown(so.state, sock, SHUT_RDWR);
			so._closesocket(so.state, sock);
			return 1;
		}
		if(is_ip_literal(ns->hostname)){
			if(!X509_VERIFY_PARAM_set1_ip_asc(param, ns->hostname)){
				SSL_free(ssl);
				so._shutdown(so.state, sock, SHUT_RDWR);
				so._closesocket(so.state, sock);
				return 1;
			}
		}
		else {
			if(!X509_VERIFY_PARAM_set1_host(param, ns->hostname, strlen(ns->hostname))){
				SSL_free(ssl);
				so._shutdown(so.state, sock, SHUT_RDWR);
				so._closesocket(so.state, sock);
				return 1;
			}
			X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
#if OPENSSL_VERSION_NUMBER >= 0x0090806fL
			SSL_set_tlsext_host_name(ssl, ns->hostname);
#endif
		}
	}
	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

	do {
		struct pollfd fds[1] = {{INVALID_SOCKET, 0, 0}};
		int sslerr;

		err = SSL_connect(ssl);
		if(err == 1) break;
		sslerr = SSL_get_error(ssl, err);
		if(sslerr == SSL_ERROR_WANT_READ){
			fds[0].fd = sock;
			fds[0].events = POLLIN;
		}
		else if(sslerr == SSL_ERROR_WANT_WRITE){
			fds[0].fd = sock;
			fds[0].events = POLLOUT;
		}
		else {
			break;
		}
		if(so._poll(so.state, fds, 1, conf.timeouts[CONNECT_TO] * 1000) <= 0 ||
		   !(fds[0].revents & (POLLOUT | POLLIN))){
			break;
		}
	} while(err != 1);

	vres = SSL_get_verify_result(ssl);
	if(err != 1 || vres != X509_V_OK){
		if(vres != X509_V_OK){
			fprintf(stderr, "3proxy DoT: TLS verification failed for %s: %s\n",
				ns->hostname ? ns->hostname : "unknown",
				X509_verify_cert_error_string(vres));
		}
		SSL_shutdown(ssl);
		SSL_free(ssl);
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		return 1;
	}

#if !defined(WITH_WOLFSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	cert = SSL_get1_peer_certificate(ssl);
#else
	cert = SSL_get_peer_certificate(ssl);
#endif
	if(!cert){
		fprintf(stderr, "3proxy DoT: no peer certificate received from %s\n",
			ns->hostname ? ns->hostname : "unknown");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		return 1;
	}
	X509_free(cert);

	ns->dot_sock = sock;
	ns->dot_ssl = (void *)ssl;
	return 0;
}

static int ssl_write_all(SSL *ssl, SOCKET sock, const unsigned char *buf, int len, int timeout_ms){
	int total = 0;
	while(total < len){
		int res = SSL_write(ssl, buf + total, len - total);
		if(res > 0){
			total += res;
		}
		else {
			int sslerr = SSL_get_error(ssl, res);
			struct pollfd fds[1] = {{INVALID_SOCKET, 0, 0}};
			fds[0].fd = sock;
			if(sslerr == SSL_ERROR_WANT_WRITE){
				fds[0].events = POLLOUT;
			}
			else if(sslerr == SSL_ERROR_WANT_READ){
				fds[0].events = POLLIN;
			}
			else {
				return -1;
			}
			if(so._poll(so.state, fds, 1, timeout_ms) <= 0 ||
			   !(fds[0].revents & (POLLOUT | POLLIN))){
				return -1;
			}
		}
	}
	return total;
}

static int ssl_read_all(SSL *ssl, SOCKET sock, unsigned char *buf, int len, int timeout_ms){
	int total = 0;
	while(total < len){
		int res = SSL_read(ssl, buf + total, len - total);
		if(res > 0){
			total += res;
		}
		else if(res == 0){
			return -1;
		}
		else {
			int sslerr = SSL_get_error(ssl, res);
			struct pollfd fds[1] = {{INVALID_SOCKET, 0, 0}};
			fds[0].fd = sock;
			if(sslerr == SSL_ERROR_WANT_READ){
				fds[0].events = POLLIN;
			}
			else if(sslerr == SSL_ERROR_WANT_WRITE){
				fds[0].events = POLLOUT;
			}
			else {
				return -1;
			}
			if(so._poll(so.state, fds, 1, timeout_ms) <= 0 ||
			   !(fds[0].revents & (POLLOUT | POLLIN))){
				return -1;
			}
		}
	}
	return total;
}

static int dot_is_alive(struct nserver *ns){
	struct pollfd pfd;
	if(ns->dot_sock == INVALID_SOCKET || !ns->dot_ssl) return 0;
	pfd.fd = ns->dot_sock;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if(so._poll(so.state, &pfd, 1, 0) > 0){
		if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)){
			return 0;
		}
		if(pfd.revents & POLLIN){
			char c;
			int r = SSL_peek((SSL *)ns->dot_ssl, &c, 1);
			if(r <= 0){
				int err = SSL_get_error((SSL *)ns->dot_ssl, r);
				if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
					return 1;
				}
				return 0;
			}
		}
	}
	return 1;
}

int dot_query(struct nserver *ns, const unsigned char *qbuf, int qlen, unsigned char *rbuf, int rsize, int timeout){
	int attempts;
	uint16_t send_hdr;
	uint16_t recv_len;
	int resp_len = -1;
	int timeout_ms = timeout * 1000;
	_3proxy_mutex_t *mtx;

	if(!ns || !ns->usetls) return -1;

	mtx = dot_get_mutex(ns);
	_3proxy_mutex_lock(mtx);
	if(!ns->usetls || !ns->hostname){
		_3proxy_mutex_unlock(mtx);
		return -1;
	}

	for(attempts = 0; attempts < 2; attempts++){
		if(!dot_is_alive(ns)){
			dot_close_conn(ns);
			if(dot_connect(ns)){
				_3proxy_mutex_unlock(mtx);
				return -1;
			}
		}

		send_hdr = htons((uint16_t)qlen);
		if(ssl_write_all((SSL *)ns->dot_ssl, ns->dot_sock, (unsigned char *)&send_hdr, 2, timeout_ms) != 2 ||
		   ssl_write_all((SSL *)ns->dot_ssl, ns->dot_sock, qbuf, qlen, timeout_ms) != qlen){
			dot_close_conn(ns);
			continue;
		}

		if(ssl_read_all((SSL *)ns->dot_ssl, ns->dot_sock, (unsigned char *)&recv_len, 2, timeout_ms) != 2){
			dot_close_conn(ns);
			continue;
		}

		recv_len = ntohs(recv_len);
		if(recv_len < 12 || recv_len > (uint16_t)rsize || recv_len > 4096){
			dot_close_conn(ns);
			break;
		}

		if(ssl_read_all((SSL *)ns->dot_ssl, ns->dot_sock, rbuf, recv_len, timeout_ms) != recv_len){
			dot_close_conn(ns);
			break;
		}

		resp_len = (int)recv_len;
		break;
	}

	_3proxy_mutex_unlock(mtx);
	return resp_len;
}

void dot_cleanup(struct nserver *ns){
	_3proxy_mutex_t *mtx;
	if(!ns) return;
#ifdef WITH_SSL
	if(!ns->usetls && !ns->dot_ssl && !ns->dot_ctx && !ns->hostname){
		ns->dot_sock = INVALID_SOCKET;
		return;
	}
	mtx = dot_get_mutex(ns);
	_3proxy_mutex_lock(mtx);
	dot_close_conn(ns);
	if(ns->dot_ctx){
		SSL_CTX_free((SSL_CTX *)ns->dot_ctx);
		ns->dot_ctx = NULL;
	}
	if(ns->hostname){
		free(ns->hostname);
		ns->hostname = NULL;
	}
	ns->usetls = 0;
	ns->usetcp = 0;
	ns->dot_sock = INVALID_SOCKET;
	_3proxy_mutex_unlock(mtx);
#else
	if(ns->hostname){
		free(ns->hostname);
		ns->hostname = NULL;
	}
	ns->usetls = 0;
	ns->usetcp = 0;
#endif
}

void dot_cleanup_all(void){
	int i;
	for(i = 0; i < MAXNSERVERS; i++){
		dot_cleanup(&nservers[i]);
	}
	dot_cleanup(&authnserver);
}
#else
void dot_init_mutexes(void){
}

int dot_query(struct nserver *ns, const unsigned char *qbuf, int qlen, unsigned char *rbuf, int rsize, int timeout){
	return -1;
}

void dot_cleanup(struct nserver *ns){
	if(!ns) return;
	if(ns->hostname){
		free(ns->hostname);
		ns->hostname = NULL;
	}
	ns->usetls = 0;
	ns->usetcp = 0;
}

void dot_cleanup_all(void){
	int i;
	for(i = 0; i < MAXNSERVERS; i++){
		dot_cleanup(&nservers[i]);
	}
	dot_cleanup(&authnserver);
}
#endif


uint32_t udpresolve(int af, unsigned char * name, unsigned char * value, uint32_t *retttl, struct clientparam* param, int makeauth){

    int i,n;
    uint32_t retval;

    if((af == AF_INET) && (retval = hashresolv(&dns_table, name, value, retttl))) {
	return retval;
    }
    if((af == AF_INET6) && (retval = hashresolv(&dns6_table, name, value, retttl))) {
	return retval;
    }
    n = (makeauth && !SAISNULL(&authnserver.addr))? 1 : numservers;
    for(i=0; i<n; i++){
	unsigned short nq, na;
	unsigned char b[4098], *buf, *s1, *s2;
	int j, k, len, flen;
	SOCKET sock;
	uint32_t ttl;
	PROXYSOCKADDRTYPE addr;
	PROXYSOCKADDRTYPE from;
	PROXYSOCKADDRTYPE *sinsr, *sinsl;
	int usetcp = 0;
	unsigned short serial = 1;
	unsigned char qbuf[300];
	int qlen;
	struct nserver *curr_ns;

	buf = b+2;

	curr_ns = (makeauth && !SAISNULL(&authnserver.addr))? &authnserver : &nservers[i];

	len = (int)strlen((char *)name);
	
	serial = myrand();
	*(unsigned short*)buf = serial; /* query id */
	buf[2] = 1; 			/* recursive */
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 1;			/* 1 request */
	buf[6] = buf[7] = 0;		/* no replies */
	buf[8] = buf[9] = 0;		/* no ns count */
	buf[10] = buf[11] = 0;		/* no additional */
	if(len > 255) {
	    len = 255;
	}
	memcpy(buf + 13, name, len);
	len += 13;
	buf[len] = 0;
	for(s2 = buf + 12; (s1 = (unsigned char *)strchr((char *)s2 + 1, '.')); s2 = s1)*s2 = (unsigned char)((s1 - s2) - 1);
	*s2 = (len - (int)(s2 - buf)) - 1;
	len++;
	buf[len++] = 0;
	buf[len++] = (makeauth == 1)? 0x0c : (af==AF_INET6? 0x1c:0x01);/* PTR:host address */
	buf[len++] = 0;
	buf[len++] = 1;			/* INET */
	qlen = len - 12;
	memcpy(qbuf, buf + 12, qlen);

	if(curr_ns->usetls){
#ifdef WITH_SSL
	    unsigned char resp[4096];
	    int q_len = len;
	    len = dot_query(curr_ns, buf, q_len, resp, sizeof(resp), conf.timeouts[DNS_TO]);
	    if(len <= 13) {
		continue;
	    }
	    memcpy(buf, resp, len);
	    if(param) {
		if(!makeauth) param->sinsr = curr_ns->addr;
		param->statscli64 += q_len;
		param->statssrv64 += len;
	    }
#else
	    continue;
#endif
	}
	else {
	    sinsl = (param && !makeauth)? &param->sinsl : &addr;
	    sinsr = (param && !makeauth)? &param->sinsr : &addr;
	    memset(sinsl, 0, sizeof(addr));
	    memset(sinsr, 0, sizeof(addr));

	    usetcp = curr_ns->usetcp;
	    *SAFAMILY(sinsl) = *SAFAMILY(&curr_ns->addr);
	    if((sock=so._socket(so.state, SASOCK(sinsl), usetcp?SOCK_STREAM:SOCK_DGRAM, usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) break;
	    if(so._bind(so.state, sock,(struct sockaddr *)sinsl,SASIZE(sinsl))){
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		break;
	    }
	    *sinsr = curr_ns->addr;
	    if(usetcp){
		if(connectwithpoll(NULL, sock,(struct sockaddr *)sinsr,SASIZE(sinsr),conf.timeouts[CONNECT_TO])) {
		    so._shutdown(so.state, sock, SHUT_RDWR);
		    so._closesocket(so.state, sock);
		    break;
		}
#ifdef TCP_NODELAY
		{
		    int opt = 1;
		    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
		}
#endif
		buf-=2;
		*(unsigned short*)buf = htons(len);
		len+=2;
	    }

	    if(socksendto(NULL, sock, (struct sockaddr *)sinsr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		continue;
	    }
	    if(param) param->statscli64 += len;
	    len = sockrecvfrom(NULL, sock, (struct sockaddr *)&from, buf, 4096, conf.timeouts[DNS_TO]*1000);
	    if(len > 13 && usetcp){
		unsigned short us;
		us = ntohs(*(unsigned short*)buf);
		len-=2;
		buf+=2;
		if(us > 4096 || us < len) len = 0;
		else if(us > len){
		    if(sockrecvfrom(NULL, sock, (struct sockaddr *)&from, buf+len, us-len, conf.timeouts[DNS_TO]*1000) != us-len) len = 0;
		    else len = us;
		}
	    }
	    so._shutdown(so.state, sock, SHUT_RDWR);
	    so._closesocket(so.state, sock);
	    if(len <= 13) {
		continue;
	    }
	    if(param) param->statssrv64 += len;
	    if(!usetcp && (*SAFAMILY(&from) != *SAFAMILY(sinsr) ||
		memcmp(SAADDR(&from), SAADDR(sinsr), SAADDRLEN(sinsr)) ||
		*SAPORT(&from) != *SAPORT(sinsr))) {
		continue;			/* not from the server we asked */
	    }
	}
	if(*(unsigned short *)buf != serial)continue;
	if(!(buf[2] & 0x80)) continue;	/* not a response */
	nq = buf[5] + (((unsigned short)buf[4])<<8);
	if (nq != 1) {
	    continue;			/* we did only 1 request */
	}
	if(len < 12 + qlen || dnsqmatch(buf + 12, qbuf, qlen)) {
	    continue;			/* question does not match the query */
	}
	if((na = buf[7] + (((unsigned short)buf[6])<<8)) < 1) {
	    return 0;
	}
	for(k = 13; k<len && buf[k]; k++) {
	}
	k++;
	if( (k+4) >= len) {
	    continue;
	}
	k += 4;
	if(na > 255) na = 255;			/* somebody is very evil */
	for (j = 0; j < na; j++) {		/* now there should be answers */
	    if(k >= len) break;
	    while(buf[k] < 192 && buf[k] !=0 && (k+buf[k]+14) < len) k+= (buf[k] + 1);
	    if(!buf[k]) k--;
	    if((k+(af == AF_INET6?28:16)) > len) {
		break;
	    }
	    flen = buf[k+11] + (((unsigned short)buf[k+10])<<8);
	    if((k+12+flen) > len) {
		break;
	    }
	    if(makeauth != 1){
		if(buf[k+2] != 0 || buf[k+3] != (af == AF_INET6?0x1c:0x1) || flen != (af == AF_INET6?16:4)) {
		    k+= (12 + flen);
		    continue; 		/* we need A IPv4 */
		}
		ttl = ntohl(*(uint32_t *)(buf + k + 6));
		memcpy(value, buf + k + 12, af == AF_INET6? 16:4);
		if(ttl < 0 || ttl > (3600*12)) ttl = 3600*12;
		if(!ttl) ttl = 1;
		hashadd(af == AF_INET6?&dns6_table:&dns_table, name, value, conf.time+ttl);
		if(retttl) *retttl = ttl;
		return 1;
	    }
	    else {
		
		if(buf[k+2] != 0 || buf[k+3] != 0x0c) {
		    k+= (12 + flen);
		    continue; 		/* we need A PTR */
		}
		s1 = buf + k + 12 + flen;	/* the end of this record's data, inside the answer */
		for (s2 = buf + k + 12; s2 < s1 && *s2 && *s2 < 64; ){
		    unsigned char *next = s2 + ((unsigned)*s2) + 1;
		    *s2 = '.';
		    s2 = next;
		}
		if(s2 >= s1 || *s2 || s2 == buf + k + 12)
		    break;	/* the name runs past its data, is compressed or empty */
		if(param->username)free(param->username);
		param->username = (unsigned char *)strdup ((char *)buf + k + 13);

		return udpresolve(af,param->username, value, NULL, NULL, 2);
	    }
	}
    }
    return 0;
}

uint32_t myresolver(int af, unsigned char * name, unsigned char * value){
 return udpresolve(af, name, value, NULL, NULL, 0);
}

uint32_t fakeresolver (int af, unsigned char *name, unsigned char * value){
 memset(value, 0, af == AF_INET6? 16 : 4);
 if(af == AF_INET6){
    memset(value, 0, 16);
    value[15] = 2;
 }
 else {
    value[0] = 127;
    value[1] = 0;
    value[2] = 0;
    value[3] = 2;
 }
 return 1;
}