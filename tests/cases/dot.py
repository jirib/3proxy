"""DNS-over-TLS (DoT, RFC 7858): native encrypted DNS upstream support."""

import socket
import ssl
import struct
import threading
import time


class DotMockServer:
    """A local DNS-over-TLS server for integration testing."""

    def __init__(self, port, certfile, keyfile, records=None, host="127.0.0.1",
                 family=socket.AF_INET):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.records = records or {}
        self.host = host
        self.family = family
        self.running = False
        self.queries_served = 0
        self.connections_accepted = 0
        self.sock = None
        self.thread = None
        self.client_socks = []
        self.lock = threading.Lock()
        self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_ctx.load_cert_chain(certfile, keyfile)

    def start(self):
        self.sock = socket.socket(self.family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(10)
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self.close_clients()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=2)

    def close_clients(self):
        with self.lock:
            for s in list(self.client_socks):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
            self.client_socks.clear()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, _ = self.sock.accept()
            except OSError:
                break
            self.connections_accepted += 1
            t = threading.Thread(target=self._handle_client, args=(client_sock,),
                                 daemon=True)
            t.start()

    def _recvall(self, s, count):
        buf = b""
        while len(buf) < count:
            try:
                chunk = s.recv(count - len(buf))
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle_client(self, client_sock):
        try:
            tls_sock = self.tls_ctx.wrap_socket(client_sock, server_side=True)
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass
            return

        with self.lock:
            self.client_socks.append(tls_sock)

        tls_sock.settimeout(5.0)
        try:
            while self.running:
                hdr = self._recvall(tls_sock, 2)
                if not hdr or len(hdr) < 2:
                    break
                qlen = struct.unpack("!H", hdr)[0]
                qdata = self._recvall(tls_sock, qlen)
                if not qdata or len(qdata) < qlen:
                    break
                self.queries_served += 1
                resp = self._make_response(qdata)
                if resp:
                    tls_sock.sendall(struct.pack("!H", len(resp)) + resp)
        except Exception:
            pass
        finally:
            with self.lock:
                if tls_sock in self.client_socks:
                    self.client_socks.remove(tls_sock)
            try:
                tls_sock.close()
            except Exception:
                pass

    def _make_response(self, qdata):
        if len(qdata) < 12:
            return None
        tx_id = qdata[:2]
        pos = 12
        labels = []
        while pos < len(qdata) and qdata[pos] != 0:
            llen = qdata[pos]
            pos += 1
            labels.append(qdata[pos:pos + llen].decode("latin1", errors="ignore"))
            pos += llen
        pos += 1
        if pos + 4 > len(qdata):
            return None
        qtype, _ = struct.unpack("!HH", qdata[pos:pos + 4])
        pos += 4
        qname = ".".join(labels).lower()

        answer_ip = self.records.get(qname)
        if answer_ip:
            if ":" in answer_ip and qtype == 28:
                # AAAA
                ip_bytes = socket.inet_pton(socket.AF_INET6, answer_ip)
                hdr = tx_id + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                qsection = qdata[12:pos]
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + ip_bytes
                return hdr + qsection + ans
            elif "." in answer_ip and qtype == 1:
                # A
                ip_bytes = socket.inet_aton(answer_ip)
                hdr = tx_id + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                qsection = qdata[12:pos]
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
                return hdr + qsection + ans

        # NXDOMAIN
        hdr = tx_id + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0)
        return hdr + qdata[12:pos]


def run(t):
    if not t.skip_unless("ssl"):
        return
    certs = t.certs()
    if not certs or not certs.verified:
        t.skip("TLS (certificates not available or failed verification)")
        return

    # --- 1. Configuration Validation -----------------------------------
    # Missing peer hostname
    res = t.run_config("dot_nohost", """
        log
        nserver tls://127.0.0.1:853
    """)
    t.contains(res, "DoT nserver requires peer hostname",
               "missing peer hostname is rejected")

    # Missing peer hostname after ?
    res = t.run_config("dot_emptyhost", """
        log
        nserver tls://127.0.0.1:853?
    """)
    t.contains(res, "DoT nserver requires peer hostname",
               "empty peer hostname is rejected")

    # Invalid peer hostname characters
    res = t.run_config("dot_badhost", """
        log
        nserver "tls://127.0.0.1:853?bad/host"
    """)
    t.contains(res, "Invalid peer hostname",
               "invalid characters in peer hostname are rejected")

    # Invalid IP address
    res = t.run_config("dot_badip", """
        log
        nserver tls://999.999.999.999:853?sni.test
    """)
    t.contains(res, "failed with code 1",
               "invalid IP address in DoT nserver is rejected")

    # --- 2. Valid DoT upstream resolution with SOCKS5 --------------------
    origin_port = t.free_port()
    dot_port = t.free_port()
    socks_port = t.free_port()

    dot_server = DotMockServer(
        dot_port, certs.server, certs.server_key,
        records={
            "app.test": "127.0.0.1",
            "one.test": "127.0.0.1",
            "two.test": "127.0.0.1",
            "three.test": "127.0.0.1",
            "reconnect.test": "127.0.0.1",
        }
    )
    dot_server.start()

    try:
        t.start("dot_socks", f"""
            log
            auth iponly
            allow *
            http echo * /echo**
            httpsrv -p{origin_port}

            flush
            ssl_client_ca_file {certs.ca}
            nserver tls://127.0.0.1:{dot_port}?sni.test
            nscache 1024
            auth iponly
            allow *
            socks -p{socks_port}
        """, ports=[origin_port, socks_port])

        socks_proxy = f"127.0.0.1:{socks_port}"
        url = f"http://app.test:{origin_port}/echo"

        r = t.socks_http(socks_proxy, url, remote_dns=True)
        t.eq(200, r.status, "SOCKS5 resolves domain via DoT and connects")
        t.contains(r, "path=/echo", "origin received request via DoT resolution")

        # --- 3. Connection Reuse across multiple queries ----------------
        # Resolving new names that are not yet in cache
        r1 = t.socks_http(socks_proxy, f"http://one.test:{origin_port}/echo", remote_dns=True)
        r2 = t.socks_http(socks_proxy, f"http://two.test:{origin_port}/echo", remote_dns=True)
        r3 = t.socks_http(socks_proxy, f"http://three.test:{origin_port}/echo", remote_dns=True)

        t.eq(200, r1.status, "first query succeeds over DoT")
        t.eq(200, r2.status, "second query succeeds over DoT")
        t.eq(200, r3.status, "third query succeeds over DoT")

        t.eq(1, dot_server.connections_accepted,
             "all consecutive DoT queries reused the same persistent TLS connection")

        # --- 4. DNS Caching (nscache) -----------------------------------
        queries_before = dot_server.queries_served
        r_cached = t.socks_http(socks_proxy, f"http://one.test:{origin_port}/echo", remote_dns=True)
        t.eq(200, r_cached.status, "cached name resolves immediately")
        t.eq(queries_before, dot_server.queries_served,
             "cached query was served from nscache without sending a DoT query")

        # --- 5. Connection Interruption and Automatic Reconnect --------
        dot_server.close_clients()
        time.sleep(0.1)
        r_rec = t.socks_http(socks_proxy, f"http://reconnect.test:{origin_port}/echo",
                             remote_dns=True)
        t.eq(200, r_rec.status, "query succeeds after connection interruption")
        t.eq(2, dot_server.connections_accepted,
             "resolver automatically opened a new TLS connection after previous closed")

    finally:
        t.stop_all()
        dot_server.stop()

    # --- 6. Certificate Verification Failure (Untrusted CA) -------------
    dot_untrusted_port = t.free_port()
    socks_untrusted = t.free_port()

    dot_untrusted = DotMockServer(
        dot_untrusted_port, certs.other, certs.other_key,
        records={"badcert.test": "127.0.0.1"}
    )
    dot_untrusted.start()

    try:
        t.start("dot_untrusted", f"""
            log
            ssl_client_ca_file {certs.ca}
            nserver tls://127.0.0.1:{dot_untrusted_port}?sni.test
            auth iponly
            allow *
            socks -p{socks_untrusted}
        """, ports=[socks_untrusted])

        r_bad = t.socks_http(f"127.0.0.1:{socks_untrusted}",
                             f"http://badcert.test:80/echo", remote_dns=True)
        t.ne(200, r_bad.status,
             "resolution fails when upstream presents an untrusted certificate")

    finally:
        t.stop_all()
        dot_untrusted.stop()

    # --- 7. Hostname Mismatch Verification ------------------------------
    dot_mismatch_port = t.free_port()
    socks_mismatch = t.free_port()

    dot_mismatch = DotMockServer(
        dot_mismatch_port, certs.server, certs.server_key,
        records={"mismatch.test": "127.0.0.1"}
    )
    dot_mismatch.start()

    try:
        t.start("dot_mismatch", f"""
            log
            ssl_client_ca_file {certs.ca}
            nserver tls://127.0.0.1:{dot_mismatch_port}?mismatch.test
            auth iponly
            allow *
            socks -p{socks_mismatch}
        """, ports=[socks_mismatch])

        r_mismatch = t.socks_http(f"127.0.0.1:{socks_mismatch}",
                                  f"http://mismatch.test:80/echo", remote_dns=True)
        t.ne(200, r_mismatch.status,
             "resolution fails when peer certificate hostname does not match configured hostname")

    finally:
        t.stop_all()
        dot_mismatch.stop()

    # --- 8. TLS Handshake Failure (Plain TCP Server) -------------------
    tcp_plain_port = t.free_port()
    socks_plain = t.free_port()

    plain_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    plain_sock.bind(("127.0.0.1", tcp_plain_port))
    plain_sock.listen(5)

    def _plain_accept():
        while True:
            try:
                conn, _ = plain_sock.accept()
                conn.close()
            except OSError:
                break

    plain_thread = threading.Thread(target=_plain_accept, daemon=True)
    plain_thread.start()

    try:
        t.start("dot_handshake_fail", f"""
            log
            ssl_client_ca_file {certs.ca}
            nserver tls://127.0.0.1:{tcp_plain_port}?sni.test
            auth iponly
            allow *
            socks -p{socks_plain}
        """, ports=[socks_plain])

        r_plain = t.socks_http(f"127.0.0.1:{socks_plain}",
                               "http://plain.test:80/echo", remote_dns=True)
        t.ne(200, r_plain.status,
             "TLS handshake failure to plain TCP port is handled without crashing")

    finally:
        t.stop_all()
        plain_sock.close()
        plain_thread.join(timeout=1)

    # --- 9. Upstream Failover -------------------------------------------
    dead_port = t.free_port()
    live_port = t.free_port()
    socks_failover = t.free_port()
    origin_failover = t.free_port()

    dot_live = DotMockServer(
        live_port, certs.server, certs.server_key,
        records={"failover.test": "127.0.0.1"}
    )
    dot_live.start()

    try:
        t.start("dot_failover", f"""
            log
            auth iponly
            allow *
            http echo * /echo**
            httpsrv -p{origin_failover}

            flush
            ssl_client_ca_file {certs.ca}
            nserver tls://127.0.0.1:{dead_port}?sni.test
            nserver tls://127.0.0.1:{live_port}?sni.test
            nscache 1024
            auth iponly
            allow *
            socks -p{socks_failover}
        """, ports=[origin_failover, socks_failover])

        r_fo = t.socks_http(f"127.0.0.1:{socks_failover}",
                            f"http://failover.test:{origin_failover}/echo", remote_dns=True)
        t.eq(200, r_fo.status,
             "resolver falls over from unresponsive upstream to second DoT upstream")

    finally:
        t.stop_all()
        dot_live.stop()

    # --- 10. dnspr with DoT upstream -----------------------------------
    dnspr_port = t.free_port()
    dot_dnspr_port = t.free_port()

    dot_dnspr = DotMockServer(
        dot_dnspr_port, certs.server, certs.server_key,
        records={"dnspr.test": "10.20.30.40"}
    )
    dot_dnspr.start()

    try:
        t.start("dot_dnspr", f"""
            log
            flush
            ssl_client_ca_file {certs.ca}
            nserver tls://127.0.0.1:{dot_dnspr_port}?sni.test
            nscache 1024
            auth iponly
            allow *
            dnspr -p{dnspr_port}
        """)

        deadline = time.time() + 5
        while time.time() < deadline:
            ans = t.dns_query(dnspr_port, "dnspr.test")
            if ans:
                break
            time.sleep(0.05)

        t.eq(["10.20.30.40"], t.dns_query(dnspr_port, "dnspr.test"),
             "dnspr resolves A record via DoT upstream")

    finally:
        t.stop_all()
        dot_dnspr.stop()

    # --- 11. IPv6 Upstream Resolution (if system has IPv6) -------------
    if t.has_ipv6():
        dot_ipv6_port = t.free_port()
        dnspr_ipv6 = t.free_port()

        dot_ipv6 = DotMockServer(
            dot_ipv6_port, certs.server, certs.server_key,
            records={"ipv6up.test": "10.30.50.70"},
            host="::1", family=socket.AF_INET6
        )
        try:
            dot_ipv6.start()
            t.start("dot_ipv6", f"""
                log
                flush
                ssl_client_ca_file {certs.ca}
                nserver tls://[::1]:{dot_ipv6_port}?sni.test
                nscache 1024
                auth iponly
                allow *
                dnspr -p{dnspr_ipv6}
            """)

            deadline = time.time() + 5
            while time.time() < deadline:
                ans = t.dns_query(dnspr_ipv6, "ipv6up.test")
                if ans:
                    break
                time.sleep(0.05)

            t.eq(["10.30.50.70"], t.dns_query(dnspr_ipv6, "ipv6up.test"),
                 "DoT resolution works over bracketed IPv6 upstream")

        finally:
            t.stop_all()
            dot_ipv6.stop()
