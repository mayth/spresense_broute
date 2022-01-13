#include "bp35a1.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/***** Private Data *****/
static const char crlf[] = {0x0d, 0x0a};

typedef struct {
  /// Command name.
  char *cmd;
  /// Number of arguments.
  int nargs;
} bp35a1_cmd;

static const bp35a1_cmd commands[] = {
    {"SKVER", 0},  {"SKSETRBID", 1}, {"SKSETPWD", 2}, {"SKSREG", 2},
    {"SKSCAN", 3}, {"SKJOIN", 1},    {"SKSENDTO", 6}};
static const int n_commands = 7;

/***** Private Function *****/

/// Sends `s` to `fd` and also sends CRLF after sending `s`.
/// This returns a number of bytes written without CRLF on success; otherwise,
/// -1.
static int write_serial(int fd, const char *s) {
  size_t len = strlen(s);
  if (len == 0) {
    return -1;
  }

  int wcount = write(fd, s, len);
  if (wcount < 0) {
    perror("bp35a1(write_serial): writing content");
    return -1;
  }

  if (write(fd, crlf, 2) < 0) {
    perror("bp35a1(write_serial): writing CRLF");
    return -1;
  }

  return wcount;
}

/// Sends a command.
/// This returns a number of characters written without CRLF on success;
/// otherwise -1.
static ssize_t send_cmd(int fd, const char *cmd, ...) {
  int nargs = -1;
  for (int i = 0; i < n_commands; ++i) {
    if (commands[i].cmd == cmd) {
      nargs = commands[i].nargs;
      break;
    }
  }
  if (nargs < 0) {
    return -1;
  }

  if (nargs == 0) {
    return write_serial(fd, cmd);
  }

  size_t written;
  size_t len;
  len = strlen(cmd);
  if (write(fd, cmd, len) < 0) {
    perror("bp35a1(send_cmd): writing command");
    return -1;
  }
  written = len;

  va_list vl;
  va_start(vl, cmd);
  for (int i = 0; i < nargs; ++i) {
    static const char *sp = " ";
    const char *arg = va_arg(vl, const char *);
    len = strlen(arg);
    if (write(fd, sp, 1) < 0) {
      perror("bp35a1(send_cmd): writing space");
      return -1;
    }
    if (write(fd, arg, len) < 0) {
      perror("bp35a1(send_cmd): writing arg");
      return -1;
    }
    written += len + 1;
  }
  va_end(vl);
  if (write(fd, crlf, 2) < 0) {
    perror("bp35a1(send_cmd): writing CRLF");
    return -1;
  }

  return written;
}

/// Reads characters from `fd` and stores it into the buffer pointed by `s`.
/// This reads at most `len`-1 characters and ensure that it is NULL terminated.
/// This stops reading after EOF or a newline (CRLF). A newline is not stored
/// into the buffer. If `len` is 0, this does nothing. If `len` is 1, this
/// stores NULL into the buffer. This returns a length of a string read (without
/// NULL and a newline) on success; otherwise, a negative value.
static ssize_t read_serial(int fd, char *s, size_t len) {
  char ch;
  size_t total = 0;

  if (len == 0) {
    return 0;
  }
  if (len == 1) {
    s[0] = '\0';
    return 0;
  }

  for (int i = 0; i < len - 1; ++i) {
    int n = read(fd, &ch, 1);
    if (n < 0) {
      perror("read_serial");
      return n;
    }
    if (n == 0) {
      break;
    }
    s[i] = ch;
    if (ch == 0x0a) {
      if (s[i - 1] == 0x0d) {
        s[i - 1] = '\0';
        --total;
      } else {
        s[i + 1] = '\0';
      }
      break;
    }
    ++total;
  }
  s[len - 1] = '\0';
  return total;
}

/// Sets up the terminal.
static int setup_term(int fd) {
  struct termios tio;
  if (tcgetattr(fd, &tio)) {
    perror("setup_term: failed to tcgetattr");
    return ERROR;
  }
  tio.c_cflag |= CREAD | CLOCAL;
  cfmakeraw(&tio);
  cfsetspeed(&tio, B115200);
  if (tcsetattr(fd, TCSANOW, &tio)) {
    perror("setup_term: failed to tcsetattr");
    return ERROR;
  }

  // ensure the settings are applied
  struct termios tio_actual;
  if (tcgetattr(fd, &tio_actual)) {
    perror("setup_term: failed to tcgetattr");
    return ERROR;
  }

#ifdef DEBUG
  if (tio.c_iflag != tio_actual.c_iflag || tio.c_oflag != tio_actual.c_oflag ||
      tio.c_lflag != tio_actual.c_lflag || tio.c_cflag != tio_actual.c_cflag ||
      tio.c_speed != tio_actual.c_cflag) {
    printf("setup_term: termios does not set properly\n");
    printf("  iflag: want 0x%04x, got 0x%04x\n", tio.c_iflag,
           tio_actual.c_iflag);
    printf("  oflag: want 0x%04x, got 0x%04x\n", tio.c_oflag,
           tio_actual.c_oflag);
    printf("  lflag: want 0x%04x, got 0x%04x\n", tio.c_lflag,
           tio_actual.c_lflag);
    printf("  cflag: want 0x%04x, got 0x%04x\n", tio.c_cflag,
           tio_actual.c_cflag);
    printf("  speed: want %d, got %d\n", tio.c_speed, tio_actual.c_speed);
  }
#endif

  tcflush(fd, TCIOFLUSH);

  return OK;
}

/***** Public Function *****/

bp35a1 *bp35a1_init(int fd) {
  if (setup_term(fd)) {
    perror("bp35a1_init: setup_term");
    return NULL;
  }

  bp35a1 *c = (bp35a1 *)malloc(sizeof(bp35a1));
  if (c == NULL) {
    perror("bp35a1_init: malloc");
    return NULL;
  }
  c->fd = fd;

  // disable echo back
  if (send_cmd(fd, "SKSREG", "SFE", "0") < 0) {
    perror("bp35a1_init: send_cmd (disabling echo back)");
    return NULL;
  }

  return c;
}

void bp35a1_close(bp35a1 *client) {
  close(client->fd);
  free(client);
}

ssize_t bp35a1_version(bp35a1 *client, char *buf) {
  int ret;
  if ((ret = send_cmd(client->fd, "SKVER")) < 0) {
    return ret;
  }
  char rbuf[16];
  memset(rbuf, 0, 16);
  // response
  if (read_serial(client->fd, rbuf, 16) < 0) {
    return BP35A1_EIO;
  }
  if (strncmp(rbuf, "EVER ", 5) != 0) {
    printf("bp35a1(version): EVER expected, got %s\n", rbuf);
    return BP35A1_ECMDFAIL;
  }
  size_t reslen = strlen(rbuf);
  strncpy(buf, rbuf + 5, reslen - 5);
  buf[reslen - 5] = '\0';

  // check "OK"
  if (read_serial(client->fd, rbuf, 16) < 0) {
    return BP35A1_EIO;
  }
  if (strcmp(rbuf, "OK") != 0) {
    printf("bp35a1(version): OK expected, got %s\n", rbuf);
    return BP35A1_ECMDFAIL;
  }

  return reslen - 5;
}

int bp35a1_start_active_scan(bp35a1 *client, uint8_t duration) {
  if (duration < 0 || 0x14 < duration) {
    return BP35A1_EARG;
  }
  char duration_s[3];
  sprintf(duration_s, "%X", duration);
  int ret;
  if ((ret = send_cmd(client->fd, "SKSCAN", "3", "FFFFFFFF", duration_s)) < 0) {
    printf(
        "bp35a1(start_active_scan): send command failure (ret=%d, errno=%d)\n",
        ret, errno);
    return ret;
  }
  return 0;
}

int bp35a1_start_ed_scan(bp35a1 *client, uint8_t duration) {
  if (duration < 0 || 0x14 < duration) {
    return BP35A1_EARG;
  }
  char duration_s[3];
  sprintf(duration_s, "%X", duration);
  int ret;
  if ((ret = send_cmd(client->fd, "SKSCAN", "0", "FFFFFFFF", duration_s)) < 0) {
    printf(
        "bp35a1(start_active_scan): send command failure (ret=%d, errno=%d)\n",
        ret, errno);
    return ret;
  }
  return 0;
}

int bp35a1_set_channel(bp35a1 *client, uint8_t chan) {
  char chan_s[3];
  sprintf(chan_s, "%02X", chan);
  return send_cmd(client->fd, "SKSREG", "S02", chan_s);
}

int bp35a1_set_pan_id(bp35a1 *client, uint16_t pan_id) {
  char pan_id_s[5];
  sprintf(pan_id_s, "%04X", pan_id);
  return send_cmd(client->fd, "SKSREG", "S03", pan_id_s);
}

int bp35a1_auth_init(bp35a1 *client, const char *rbid, const char *pwd) {
  size_t rbid_len = strlen(rbid);
  // Route-B ID should be 32 bytes.
  // ref: command manual "3.17. SKSETRBID" (pp.28)
  if (rbid_len != 32) {
    return -1;
  }
  int ret;
  if ((ret = send_cmd(client->fd, "SKSETRBID", rbid)) < 0) {
    perror("bp35a1: auth_init: send_cmd(SKSETRBID)");
    return ret;
  }
  // check response
  char rbuf[16];
  if ((ret = read_serial(client->fd, rbuf, 16)) < 0) {
    perror("bp35a1: auth_init: read_serial");
    return ret;
  }
  if (strcmp(rbuf, "OK") != 0) {
    printf("bp35a1: auth_init: SKSETRBID expected OK, got %s\n", rbuf);
    return BP35A1_ECMDFAIL;
  }

  size_t pwdlen = strlen(pwd);
  if (pwdlen < 1 || 32 < pwdlen) {
    return BP35A1_EARG;
  }
  char hexlen[3];
  sprintf(hexlen, "%x", pwdlen);

  if ((ret = send_cmd(client->fd, "SKSETPWD", hexlen, pwd)) < 0) {
    perror("bp35a1: auth_init: send_cmd(SKSETPWD)");
    return ret;
  }
  if ((ret = read_serial(client->fd, rbuf, 16)) < 0) {
    perror("bp35a1: auth_init: read_serial");
    return BP35A1_EIO;
  }
  if (strcmp(rbuf, "OK") != 0) {
    printf("bp35a1: auth_init: SKSETPWD expected OK, got %s\n", rbuf);
    return BP35A1_ECMDFAIL;
  }

  return 0;
}

int bp35a1_start_scan(bp35a1 *client) {
  int ret;
  if ((ret = send_cmd(client->fd, "SKSCAN", "3", "FFFFFFFF", "6")) < 0) {
    return ret;
  }
  return 0;
}

int bp35a1_join(bp35a1 *client, const char *addr) {
  if (addr == NULL) {
    return BP35A1_EARG;
  }
  size_t addrlen = strlen(addr);
  // string representation of IPv6 address should have 39 bytes.
  if (addrlen != 39) {
    return BP35A1_EARG;
  }
  int ret;
  if ((ret = send_cmd(client->fd, "SKJOIN", addr)) < 0) {
    return ret;
  }
  return 0;
}

int bp35a1_sendto(bp35a1 *client, uint8_t handle, const char *addr,
                  uint16_t port, bool sec, size_t len, const uint8_t *data) {
  char *buf = malloc(65);
  sprintf(buf, "%s %X %s %04X %c %04X ", "SKSENDTO", handle, addr, port,
          sec ? '1' : '0', len);
  size_t param_len = strlen(buf);
  int ret;
  if ((ret = write(client->fd, buf, param_len)) < 0) {
    perror("bp35a1_sendto: write SKSENDTO & its param");
    return BP35A1_EIO;
  }
  if ((ret = write(client->fd, data, len)) < 0) {
    perror("bp35a1_sendto: write packet content");
    return BP35A1_EIO;
  }
  return 0;
}
