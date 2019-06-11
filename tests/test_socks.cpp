/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "testutil.hpp"
#include "testutil_unity.hpp"


SETUP_TEARDOWN_TESTCONTEXT

char socks_server_address[MAX_SOCKET_STRING];
char connect_address[MAX_SOCKET_STRING];

void recvall (int sock_fd, char *buffer, int len)
{
    int res;
    int total = 0;
    while (len - total > 0) {
        res = recv (sock_fd, buffer + total, len - total, 0);
        if (res == -1)
            fprintf (stderr, "socks_server: error receiving %d bytes: %d %d\n",
                     len, res, errno);
        TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
        TEST_ASSERT (res != 0);
        total += res;
    }
    TEST_ASSERT (total == len);
}

int recvonce (int sock_fd, char *buffer, int len)
{
    int res;
    res = recv (sock_fd, buffer, len, 0);
    if (res == -1)
        fprintf (stderr, "socks_server: error receiving bytes: %d %d\n", res,
                 errno);
    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
    return res;
}

void sendall (int sock_fd, char *buffer, int len)
{
    int res;
    int total = 0;
    while (len - total > 0) {
        res = send (sock_fd, buffer + total, len - total, 0);
        if (res == -1)
            fprintf (stderr, "socks_server: error sending %d bytes: %d %d\n",
                     len, res, errno);
        TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
        TEST_ASSERT (res != 0);
        total += res;
    }
}

int remote_connect (int socket, uint32_t addr, uint16_t port)
{
    int res;
    struct sockaddr_in ip4addr;
    ip4addr.sin_family = AF_INET;
    ip4addr.sin_addr.s_addr = htonl (addr);
    ip4addr.sin_port = htons (port);
    res = connect (socket, (struct sockaddr *) &ip4addr, sizeof ip4addr);
    return res;
}

void socks_server (const char *username, const char *password)
{
    int max_client_connect = 1;
    fprintf (stderr, "socks_server: starting server thread\n");
    fd_t server = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_NOT_EQUAL (-1, server);
    int flag = 1;
    int res;
    res = setsockopt (server, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
    struct sockaddr_in saddr = bind_bsd_socket (server);
    snprintf (socks_server_address, sizeof socks_server_address, "127.0.0.1:%d",
              ntohs (saddr.sin_port));
    res = listen (server, max_client_connect);
    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);

    int auth_method;
    if (username == NULL || username[0] == '\0') {
        auth_method = 0x0; /* No auth */
    } else {
        auth_method = 0x2; /* Basic auth */
        if (password == NULL)
            password = "";
    }

    fprintf (stderr, "socks_server: listening at address: %s\n",
             socks_server_address);
    int count = 0;
    while (count < max_client_connect) {
        int client = -1;
        do {
            char buffer[4096];
            while (1) {
                client = accept (server, NULL, NULL);
                if (client >= 0)
                    break;
                if (client == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
                    TEST_ASSERT_SUCCESS_RAW_ERRNO (client);
                msleep (SETTLE_TIME);
            }
            count++;
            fprintf (
              stderr,
              "socks_server: accepted client connection %d/%d: client fd %d\n",
              count, max_client_connect, client);

            /* Greetings [version, nmethods, methods...]. */
            recvall (client, buffer, 2);
            TEST_ASSERT (buffer[0] == 0x5);
            int nmethods = buffer[1];
            int method = 0xff;
            recvall (client, buffer, nmethods);
            for (int i = 0; i < nmethods; i++) {
                if (buffer[i] == auth_method)
                    method = auth_method;
            }
            fprintf (stderr, "socks_server: received greetings\n");

            /* Greetings response [version, method]. */
            buffer[0] = 0x5;
            buffer[1] = method;
            sendall (client, buffer, 2);
            fprintf (stderr,
                     "socks_server: answered greetings (method: 0x%x)\n",
                     method);

            if (method == 0xff)
                break; /* Out of client connection */

            if (method == 0x2) {
                int len;
                int err = 0;
                recvall (client, buffer, 1);
                if (buffer[0] != 0x1) {
                    err = 1;
                } else {
                    recvall (client, buffer, 1);
                    len = (unsigned char) buffer[0];
                    recvall (client, buffer, len);
                    buffer[len] = '\0';
                    if (strcmp (username, buffer) != 0) {
                        fprintf (stderr,
                                 "socks_server: error on username check: '%s', "
                                 "expected: '%s'\n",
                                 buffer, username);
                        err = 1;
                    }
                    recvall (client, buffer, 1);
                    len = (unsigned char) buffer[0];
                    recvall (client, buffer, buffer[0]);
                    buffer[len] = '\0';
                    if (strcmp (password, buffer) != 0) {
                        fprintf (stderr,
                                 "socks_server: error on password check: '%s', "
                                 "expected: '%s'\n",
                                 buffer, password);
                        err = 1;
                    }
                }
                fprintf (stderr, "socks_server: received credentials\n");
                buffer[0] = 0x1;
                buffer[1] = err;
                sendall (client, buffer, 2);
                fprintf (stderr,
                         "socks_server: answered credentials (err: 0x%x)\n",
                         err);
                if (err != 0)
                    break; /* Out of client connection. */
            }

            /* Request [version, cmd, rsv, atype, dst.addr, dst.port */
            /* Currently test only connect on IP V4 atyp */
            recvall (client, buffer, 4);
            TEST_ASSERT (buffer[0] == 0x5);
            TEST_ASSERT (buffer[1] == 0x1); /* CONNECT cmd */
            fprintf (stderr, "socks_server: received command (cmd: %d)\n",
                     buffer[3]);
            /* IPv4 ADDR & PORT */
            uint32_t naddr = 0, bind_naddr = 0;
            uint16_t nport = 0, bind_nport = 0;
            int remote = -1;
            int err = 0;
            if (buffer[3] == 0x1) /* ATYPE IPv4 */ {
                recvall (client, (char *) &naddr, 4);
                fprintf (stderr,
                         "socks_server: received address (addr: 0x%x)\n",
                         ntohl (naddr));
            } else if (buffer[3] == 0x3) /* ATYPE DOMAINNAME */ {
                int len;
                recvall (client, buffer, 1);
                len = (unsigned char) buffer[0];
                recvall (client, buffer, buffer[0]);
                buffer[len] = '\0';
                fprintf (stderr,
                         "socks_server: received domainname (hostname: %s)\n",
                         buffer);
                /* For the test we only support static resolution of "localhost" */
                if (strcmp ("localhost", buffer) == 0) {
                    naddr = htonl (0x7f000001); /* 127.0.0.1 */
                } else {
                    err = 0x4; /* Host unreachable */
                }
            } else {
                err = 0x8;
                ; /* ATYPE not supported */
            }
            recvall (client, (char *) &nport, 2);
            fprintf (stderr, "socks_server: received port (port: %d)\n",
                     ntohs (nport));
            if (err == 0) {
                fprintf (stderr, "socks_server: trying to connect to %x:%d\n",
                         ntohl (naddr), ntohs (nport));
                remote = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
                res = remote_connect (remote, ntohl (naddr), ntohs (nport));
                if (res != 0) {
                    err = 0x5; /* Connection refused */
                } else {
                    struct sockaddr_in ip4addr;
                    socklen_t len = sizeof (ip4addr);
                    res =
                      getsockname (remote, (struct sockaddr *) &ip4addr, &len);
                    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
                    bind_naddr = ip4addr.sin_addr.s_addr;
                    bind_nport = ip4addr.sin_port;
                }
            }

            /* Reply request */
            buffer[0] = 0x5;
            buffer[1] = err;
            buffer[2] = 0;
            buffer[4] = 0x1;
            sendall (client, buffer, 4);
            sendall (client, (char *) &bind_naddr, 4);
            sendall (client, (char *) &bind_nport, 2);
            fprintf (stderr, "socks_server: replied to request (err: 0x%x)\n",
                     err);
            if (err != 0)
                break; /* Out of client connection. */

            /* Communication loop */
            zmq_pollitem_t items[] = {
              {NULL, client, ZMQ_POLLIN, 0},
              {NULL, remote, ZMQ_POLLIN, 0},
            };
            fprintf (stderr,
                     "socks_server: waiting for input (client fd: %d, remote "
                     "fd: %d)\n",
                     client, remote);
            while (1) {
                if (client == -1 || remote == -1)
                    break;
                if (zmq_poll (items, 2, -1) < 0)
                    break;
                int nbytes;
                for (int i = 0; i < 2; i++) {
                    if ((items[i].revents & ZMQ_POLLIN) == 0)
                        continue;
                    fprintf (stderr, "socks_server: ready to read from fd %d\n",
                             items[i].fd);
                    int write_fd, read_fd = items[i].fd;
                    if (read_fd == client) {
                        write_fd = remote;
                    } else {
                        write_fd = client;
                    }
                    nbytes = recvonce (read_fd, buffer, sizeof buffer);
                    if (nbytes == -1)
                        continue;
                    if (nbytes == 0) {
                        /* End of stream */
                        if (read_fd == client) {
                            close (client);
                            client = -1;
                        }
                        if (read_fd == remote) {
                            close (remote);
                            remote = -1;
                        }
                        break;
                    }
                    sendall (write_fd, buffer, nbytes);
                }
            }
            if (remote != -1) {
                close (remote);
            }
            fprintf (
              stderr,
              "socks_server: closed remote connection %d/%d: client fd %d\n",
              count, max_client_connect, client);
        } while (0); /* Client socket scope. */
        if (client != -1) {
            close (client);
        }
        fprintf (stderr,
                 "socks_server: closed client connection %d/%d: client fd %d\n",
                 count, max_client_connect, client);
    }
    close (server);
    fprintf (stderr, "socks_server: closed server\n");
}

void socks_server_no_auth (void * /*unused_*/)
{
    socks_server (NULL, NULL);
}

void socks_server_basic_auth (void * /*unused_*/)
{
    socks_server ("someuser", "somepass");
}

void socks_server_basic_auth_no_pass (void * /*unused_*/)
{
    socks_server ("someuser", NULL);
}

void *setup_push_server (void)
{
    int res;
    const char *bind_address = "tcp://127.0.0.1:*";
    void *push = test_context_socket (ZMQ_PUSH);
    res = zmq_bind (push, bind_address);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    size_t len = sizeof connect_address;
    res = zmq_getsockopt (push, ZMQ_LAST_ENDPOINT, connect_address, &len);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    fprintf (stderr, "Push server bound to: %s\n", connect_address);
    return push;
}

void *setup_pull_client (const char *socks_proxy)
{
    int res;
    void *pull = test_context_socket (ZMQ_PULL);
    if (socks_proxy != NULL) {
        res = zmq_setsockopt (pull, ZMQ_SOCKS_PROXY, socks_proxy,
                              strlen (socks_proxy));
        TEST_ASSERT_SUCCESS_ERRNO (res);
    }
    res = zmq_connect (pull, connect_address);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    fprintf (stderr, "Pull client connected to: %s\n", connect_address);
    return pull;
}

#ifdef ZMQ_BUILD_DRAFT_API
void *setup_pull_client_with_auth (const char *socks_proxy,
                                   const char *username,
                                   const char *password)
{
    int res;
    void *pull = test_context_socket (ZMQ_PULL);

    if (socks_proxy != NULL) {
        res = zmq_setsockopt (pull, ZMQ_SOCKS_PROXY, socks_proxy,
                              strlen (socks_proxy));
        TEST_ASSERT_SUCCESS_ERRNO (res);
    }

    res = zmq_setsockopt (pull, ZMQ_SOCKS_USERNAME, username,
                          username == NULL ? 0 : strlen (username));
    TEST_ASSERT_SUCCESS_ERRNO (res);

    res = zmq_setsockopt (pull, ZMQ_SOCKS_PASSWORD, password,
                          password == NULL ? 0 : strlen (password));
    TEST_ASSERT_SUCCESS_ERRNO (res);

    res = zmq_connect (pull, connect_address);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    fprintf (stderr, "Pull client connected to: %s\n", connect_address);
    return pull;
}
#endif

void communicate (void *push, void *pull)
{
    fprintf (stderr, "remote: sending 2 messages\n");
    s_send_seq (push, "ABC", SEQ_END);
    s_send_seq (push, "DEF", SEQ_END);

    fprintf (stderr, "client: receiving 2 messages\n");
    s_recv_seq (pull, "ABC", SEQ_END);
    s_recv_seq (pull, "DEF", SEQ_END);
}

void test_socks_no_socks (void)
{
    void *push = setup_push_server ();
    void *pull = setup_pull_client (NULL);
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);
}

void test_socks_no_auth (void)
{
    void *thread = zmq_threadstart (&socks_server_no_auth, NULL);

    void *push = setup_push_server ();
    void *pull = setup_pull_client (socks_server_address);
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_basic_auth (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *thread = zmq_threadstart (&socks_server_basic_auth, NULL);

    void *push = setup_push_server ();
    void *pull = setup_pull_client_with_auth (socks_server_address, "someuser",
                                              "somepass");
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_empty_user (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *thread = zmq_threadstart (&socks_server_no_auth, NULL);

    void *push = setup_push_server ();
    void *pull = setup_pull_client_with_auth (socks_server_address, "", NULL);
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_null_user (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *thread = zmq_threadstart (&socks_server_no_auth, NULL);

    void *push = setup_push_server ();
    void *pull = setup_pull_client_with_auth (socks_server_address, NULL, NULL);
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_empty_pass (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *thread = zmq_threadstart (&socks_server_basic_auth_no_pass, NULL);

    void *push = setup_push_server ();
    void *pull =
      setup_pull_client_with_auth (socks_server_address, "someuser", "");
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_null_pass (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *thread = zmq_threadstart (&socks_server_basic_auth_no_pass, NULL);

    void *push = setup_push_server ();
    void *pull =
      setup_pull_client_with_auth (socks_server_address, "someuser", NULL);
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_socks_no_socks);
    RUN_TEST (test_socks_no_auth);
    RUN_TEST (test_socks_basic_auth);
    RUN_TEST (test_socks_basic_auth_empty_user);
    RUN_TEST (test_socks_basic_auth_null_user);
    RUN_TEST (test_socks_basic_auth_empty_pass);
    RUN_TEST (test_socks_basic_auth_null_pass);
    return UNITY_END ();
}
