#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sdk/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/boardctl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "bp35a1.h"
#include "echonet_lite.h"

/***** Helper *****/
static void str_mac_addr(char *s, const uint8_t addr[8]) {
  for (int i = 0; i < 8; ++i) {
    sprintf(s + i * 2, "%02X", addr[i]);
  }
}

static void str_ipv6_addr(char *s, const uint8_t addr[16]) {
  char t[4];
  for (int i = 0; i < 16; ++i) {
    const char *fmt = (i > 0 && i % 2 == 0) ? ":%02X" : "%02X";
    sprintf(t, fmt, addr[i]);
    strcat(s, t);
  }
}

/***** Constants / Enums *****/
/// Channel.
typedef enum {
  CHANNEL_33 = 0x21,
  CHANNEL_34 = 0x22,
  CHANNEL_35 = 0x23,
  CHANNEL_36 = 0x24,
  CHANNEL_37 = 0x25,
  CHANNEL_38 = 0x26,
  CHANNEL_39 = 0x27,
  CHANNEL_40 = 0x28,
  CHANNEL_41 = 0x29,
  CHANNEL_42 = 0x2A,
  CHANNEL_43 = 0x2B,
  CHANNEL_44 = 0x2C,
  CHANNEL_45 = 0x2D,
  CHANNEL_46 = 0x2E,
  CHANNEL_47 = 0x2F,
  CHANNEL_48 = 0x30,
  CHANNEL_49 = 0x31,
  CHANNEL_50 = 0x32,
  CHANNEL_51 = 0x33,
  CHANNEL_52 = 0x34,
  CHANNEL_53 = 0x35,
  CHANNEL_54 = 0x36,
  CHANNEL_55 = 0x37,
  CHANNEL_56 = 0x38,
  CHANNEL_57 = 0x39,
  CHANNEL_58 = 0x3A,
  CHANNEL_59 = 0x3B,
  CHANNEL_60 = 0x3C,
  NUM_CHANNELS = 28
} Channel;

/// Calculates an index from channel.
#define chan_to_idx(chan) (chan - 33)

#define idx_to_chan(idx) (idx + 33)

/// Event description number in EVENT event.
typedef enum {
  NS_RECEIVED = 0x01,
  NA_RECEIVED = 0x02,
  ECHO_REQ_RECEIVED = 0x05,
  ED_SCAN_DONE = 0x1F,
  BEACON_RECEIVED = 0x20,
  UDP_SEND_DONE = 0x21,
  ACTIVE_SCAN_DONE = 0x22,
  PANA_CONNECT_FAIL = 0x24,
  PANA_CONNECT_DONE = 0x25,
  SESSION_CLOSE_REQ = 0x26,
  PANA_SESS_CLOSED = 0x27,
  CLOSE_REQ_TIMEOUT = 0x28,
  PANA_SESS_TIMEOUT = 0x29,
  SEND_LIMIT = 0x32,
  SEND_LIMIT_LIFTED = 0x33
} EventID;

/***** State *****/
/// PANA session status.
typedef enum {
  /// PANA session is not established yet, or already closed.
  NOT_CONNECTED,
  /// Starting session.
  CONNECTING,
  /// PANA session is started.
  CONNECTED
} PANAStatus;

/// Scanning status.
typedef enum {
  /// No scan is running.
  NOT_SCANNING,
  /// ED scan is running.
  ED_SCAN,
  /// Active scan is running.
  ACTIVE_SCAN
} ScanStatus;

/// An information of connecting PAN.
/// This information is valid while `pana_status` is `CONNECTING` or
/// `CONNECTED`.
typedef struct {
  Channel chan;
  uint16_t pan_id;
  uint8_t mac_addr[8];
  uint8_t addr[16];
} PANAPeer;

static void print_peer_info(const PANAPeer *peer) {
  char peer_mac_addr_s[17];
  str_mac_addr(peer_mac_addr_s, peer->mac_addr);
  char peer_ipv6_addr_s[40];
  str_ipv6_addr(peer_ipv6_addr_s, peer->addr);
  printf("Peer: Channel=%02X, MACAddr=%s, Addr=%s, PanID=%04X\n", peer->chan,
         peer_mac_addr_s, peer_ipv6_addr_s, peer->pan_id);
}

typedef void (*TransactionHandlerFunc)(ELFrame *);

typedef struct {
  uint16_t tid;
  TransactionHandlerFunc f;
} TransactionHandler;

typedef struct _thl_node THLNode;

struct _thl_node {
  TransactionHandler *h;
  THLNode *next;
};

THLNode *thlnode_new(TransactionHandler *h) {
  THLNode *node = (THLNode *)malloc(sizeof(THLNode));
  if (node == NULL) {
    return NULL;
  }
  node->h = h;
  node->next = NULL;
  return node;
}

void thlnode_delete(THLNode *node) {
  if (node != NULL) {
    node->h = NULL;
    node->next = NULL;
    free(node);
  }
}

typedef struct {
  THLNode *head;
  size_t len;
} TransactionHandlerList;

TransactionHandlerList *thlist_new() {
  TransactionHandlerList *l =
      (TransactionHandlerList *)malloc(sizeof(TransactionHandlerList));
  if (l == NULL) {
    return NULL;
  }
  l->head = NULL;
  l->len = 0;
  return l;
}

void thlist_delete(TransactionHandlerList *l) {
  if (l != NULL) {
    l->head = NULL;
    l->len = 0;
    free(l);
  }
}

size_t thlist_len(const TransactionHandlerList *l) {
  assert(l != NULL);
  return l->len;
}

bool thlist_is_empty(const TransactionHandlerList *l) {
  assert(l != NULL);
  return thlist_len(l) == 0;
}

void thlist_add(TransactionHandlerList *l, TransactionHandler *h) {
  assert(l != NULL);
  THLNode *node = thlnode_new(h);
  if (node == NULL) {
    return;
  }
  if (l->head == NULL) {
    l->head = node;
  } else {
    THLNode *p = l->head;
    while (p->next != NULL) {
      p = p->next;
    }
    p->next = node;
  }
  ++l->len;
}

TransactionHandler *thlist_get(TransactionHandlerList *l, uint16_t tid) {
  assert(l != NULL);
  for (THLNode *p = l->head; p != NULL; p = p->next) {
    if (p->h->tid == tid) {
      return p->h;
    }
  }
  return NULL;
}

void thlist_remove(TransactionHandlerList *l, uint16_t tid) {
  assert(l != NULL);
  THLNode *prev = NULL, *p;
  for (p = l->head; p != NULL; prev = p, p = p->next) {
    if (p->h->tid == tid) {
      if (prev == NULL) {
        // head
        l->head = p->next;
      } else {
        prev->next = p->next;
      }
      thlnode_delete(p);
      --l->len;
    }
  }
}

typedef enum {
  RS_NO_RESPONSE = -1,
  RS_OK = 0,
  /// Reserved.
  RS_ER01,
  /// Reserved.
  RS_ER02,
  /// Reserved.
  RS_ER03,
  /// A command is not supported.
  RS_ER04,
  /// A number of arguments is invalid.
  RS_ER05,
  /// Malformed arguments, or domain error.
  RS_ER06,
  /// Reserved.
  RS_ER07,
  /// Reserved.
  RS_ER08,
  /// A UART input error occurred.
  RS_ER09,
  /// A command is accepted, but its execution is failed.
  RS_ER10
} ResponseStatus;

typedef struct {
  /// A file descriptor to contact with BP35A1.
  int fd;
  /// A PANA session status.
  PANAStatus pana_status;
  /// A scanning status.
  ScanStatus scan_status;
  /// An information of PANA coordinator.
  PANAPeer *peer;
  /// Determines whether the sending restriction is activated.
  bool is_send_restricted;
  /// A list of transactions that waits to be finished.
  TransactionHandlerList *handlers;

  /// A status of the last response.
  /// * when < 0, no response are received yet.
  /// * when = 0, received "OK".
  /// * when > 0, received "FAIL ERXX", stored error number.
  ResponseStatus response;
} Context;

static Context *context_new() {
  Context *ctx = (Context *)malloc(sizeof(Context));
  ctx->fd = -1;
  ctx->pana_status = NOT_CONNECTED;
  ctx->scan_status = NOT_SCANNING;
  ctx->peer = NULL;
  ctx->is_send_restricted = false;
  ctx->handlers = thlist_new();
  return ctx;
}

static void context_delete(Context *ctx) { free(ctx); }

static void context_begin_transaction(Context *ctx, uint16_t tid,
                                      TransactionHandlerFunc handle_func) {
  TransactionHandler *th =
      (TransactionHandler *)malloc(sizeof(TransactionHandler));
  if (th == NULL) {
    return;
  }
  th->tid = tid;
  th->f = handle_func;
  thlist_add(ctx->handlers, th);
}

static void context_done_transaction(Context *ctx, ELFrame *frame) {
  if (thlist_is_empty(ctx->handlers)) {
    return;
  }

  TransactionHandler *th = thlist_get(ctx->handlers, frame->tid);
  if (th != NULL) {
    printf("context(done_transaction): found transaction %d\n", frame->tid);
    th->f(frame);
    thlist_remove(ctx->handlers, frame->tid);
    free(th);
  } else {
    printf("context(done_transaction): transaction %d not found\n", frame->tid);
  }
}

static ResponseStatus context_wait_response(Context *ctx, uint32_t timeout) {
  time_t start = time(NULL);
  time_t deadline = start + timeout;
  ctx->response = RS_NO_RESPONSE;
  while (time(NULL) < deadline && ctx->response == RS_NO_RESPONSE) {
    usleep(1);
  }
  return ctx->response;
}

static void parse_ipv6_addr(const char *addr, uint8_t result[16]) {
  char s[3];
  for (int i = 0; i < 16; ++i) {
    strncpy(s, addr + i * 2 + i / 2, 2);
    result[i] = strtoul(s, NULL, 16);
  }
}

static void parse_mac_addr(const char *addr, uint8_t result[8]) {
  char s[3];
  for (int i = 0; i < 8; ++i) {
    strncpy(s, addr + i * 2, 2);
    result[i] = strtoul(s, NULL, 16);
  }
}

static void calculate_ipv6_from_mac_addr(const uint8_t mac_addr[8],
                                         uint8_t ipv6_addr[16]) {
  static const uint8_t ipv6_prefix[] = {0xFE, 0x80, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00};
  memcpy(ipv6_addr, ipv6_prefix, 8);
  memcpy(ipv6_addr + 8, mac_addr, 8);
  // 2nd bit from LSB in 1st byte is flipped
  ipv6_addr[8] ^= 0x02;
}

static void handle_measured_inst_res(ELFrame *frame) {
  if (frame->ehd2 != DEFINED_FORM) {
    printf("handle_measured_inst_res: EDATA is not fixed form\n");
    return;
  }
  ELDefiendData *edata = frame->edata.defined;
  if (edata->esv != ESV_GET_RES) {
    printf("handle_measured_inst_res: ESV is %02X, not Get_Res\n", edata->esv);
    return;
  }
  if (edata->opc == 0) {
    printf("handle_measured_inst_res: there is no properties\n");
    return;
  }
  for (int i = 0; i < edata->opc; ++i) {
    ELProperty *prop = edata->properties[i];
    if (prop->epc == ELHPC_MEASURED_INST_EN) {
      int32_t w = prop->edt[0] << 24 | prop->edt[1] << 16 | prop->edt[2] << 8 |
                  prop->edt[3] << 0;
      printf("handle_measured_inst_res: Energy: %d W (%08X)\n", w, w);
    } else if (prop->epc == ELHPC_MEASURED_INST_CR) {
      int16_t ph_r = prop->edt[0] << 8 | prop->edt[1];
      int16_t ph_t = prop->edt[2] << 8 | prop->edt[3];
      printf(
          "handle_measured_inst_res: Currents: R=%.2f (%04X), T=%.2f (%04X)\n",
          (float)(ph_r) / 10.0, ph_r, (float)(ph_t) / 10.0, ph_t);
    }
  }
}

static void handle_notification(ELFrame *frame) {
  if (frame->ehd2 != DEFINED_FORM) {
    printf("handle_notification: EDATA is not fixed form\n");
    return;
  }
  ELDefiendData *edata = frame->edata.defined;
  if (edata->esv != ESV_INF) {
    printf("handle_notification: ESV is %02X, not INF\n", edata->esv);
    return;
  }
  if (edata->opc == 0) {
    printf("handle_notification: there is no properties\n");
    return;
  }
  for (int i = 0; i < edata->opc; ++i) {
    ELProperty *prop = edata->properties[i];
    if (prop->epc == ELHPC_FIXED_CUMULATIVE_AMT) {
      uint16_t year = prop->edt[0] << 8 | prop->edt[1];
      uint8_t month = prop->edt[2];
      uint8_t day = prop->edt[3];
      uint8_t hour = prop->edt[4];
      uint8_t min = prop->edt[5];
      uint8_t sec = prop->edt[6];
      uint32_t kwh = prop->edt[7] << 24 | prop->edt[8] << 16 |
                     prop->edt[9] << 8 | prop->edt[10];
      printf("handle_notification: %04d-%02d-%02d %02d:%02d:%02d: %d kWh "
             "(%04X) normal\n",
             year, month, day, hour, min, sec, kwh, kwh);
    } else if (prop->epc == ELHPC_FIXED_CUMULATIVE_AMT_REV) {
      uint16_t year = prop->edt[0] << 8 | prop->edt[1];
      uint8_t month = prop->edt[2];
      uint8_t day = prop->edt[3];
      uint8_t hour = prop->edt[4];
      uint8_t min = prop->edt[5];
      uint8_t sec = prop->edt[6];
      uint32_t kwh = prop->edt[7] << 24 | prop->edt[8] << 16 |
                     prop->edt[9] << 8 | prop->edt[10];
      printf("handle_notification: %04d-%02d-%02d %02d:%02d:%02d: %d kWh "
             "(%04X) reverse\n",
             year, month, day, hour, min, sec, kwh, kwh);
    } else if (prop->epc == NPPC_INST_LIST) {
      uint8_t ninst = prop->edt[0];
      printf("handle_notification: instance list (%d):\n", ninst);
      int pos = 1;
      for (int j = 0; j < ninst; ++j) {
        EOJ eoj;
        memcpy(&eoj, prop->edt + pos, 3);
        printf("  [%d] %02X %02X %02X\n", j, eoj.class_group_code,
               eoj.class_code, eoj.instance_code);
        pos += 3;
      }
    }
  }
}

static const char crlf[] = {0x0d, 0x0a};

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
    return -1;
  }

  if (write(fd, crlf, 2) < 0) {
    return -1;
  }

  return wcount;
}

/// Sends a command.
/// This returns a number of characters written without CRLF on success;
/// otherwise -1.
static ssize_t send_cmd(int fd, const char *cmd, size_t nargs, ...) {
  if (nargs == 0) {
    return write_serial(fd, cmd);
  }

  size_t written;
  size_t len;
  len = strlen(cmd);
  if (write(fd, cmd, len) < 0) {
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
      return -1;
    }
    if (write(fd, arg, len) < 0) {
      return -1;
    }
    written += len + 1;
  }
  va_end(vl);
  if (write(fd, crlf, 2) < 0) {
    return -1;
  }

  return written;
}

/***** Event Handlers *****/
void handler_erxudp(Context *ctx, uint8_t sender[16], uint8_t dest[16],
                    uint16_t rport, uint16_t lport, uint8_t sender_lla[8],
                    bool secured, uint16_t len, const uint8_t *data) {
  printf("received UDP packet\n");
  printf("  Sender = ");
  for (int i = 0; i < 16; ++i) {
    if (i > 0 && i % 2 == 0) {
      printf(":");
    }
    printf("%02X", sender[i]);
  }
  printf("\n");
  if (lport != EL_PORT) {
    printf("packet destinated %d, not %d. skip parsing UDP...\n", lport,
           EL_PORT);
    return;
  }
  printf("  Payload (%d bytes) =", len);
  for (size_t i = 0; i < len; ++i) {
    printf(" %02X", data[i]);
  }
  printf("\n");
  int ret;
  ELFrame *frame = (ELFrame *)malloc(sizeof(ELFrame));
  if ((ret = parse_frame(data, len, frame)) < 0) {
    printf("failed to parse frame (ret=%d, errno=%d)\n", ret, errno);
    return;
  }
  printf("FRAME: ehd2=%02X, tid=%d\n", frame->ehd2, frame->tid);
  switch (frame->ehd2) {
  case ARBITRARY_FORM:
    printf("  CONTENT: ");
    for (int i = 0; i < frame->edata.arbitrary_data.size; ++i) {
      printf("%02X ", frame->edata.arbitrary_data.data[i]);
    }
    printf("\n");
    break;
  case DEFINED_FORM:
    printf("  CONTENT:\n");
    printf("    SEOJ    = %02X %02X %02X\n",
           frame->edata.defined->sender.class_group_code,
           frame->edata.defined->sender.class_code,
           frame->edata.defined->sender.instance_code);
    printf("    DEOJ    = %02X %02X %02X\n",
           frame->edata.defined->dest.class_group_code,
           frame->edata.defined->dest.class_code,
           frame->edata.defined->dest.instance_code);
    printf("    Service = %02X\n", frame->edata.defined->esv);
    printf("    # Props = %d\n", frame->edata.defined->opc);
    for (int i = 0; i < frame->edata.defined->opc; ++i) {
      ELProperty *prop = frame->edata.defined->properties[i];
      printf("    Property %d:\n", i);
      printf("      EPC: %02X\n", prop->epc);
      printf("      PDT: ");
      for (int j = 0; j < prop->pdc; ++j) {
        printf("%02X ", prop->edt[j]);
      }
      printf("\n");
    }
    switch (frame->edata.defined->esv) {
    case ESV_GET_RES:
      context_done_transaction(ctx, frame);
      break;
    case ESV_INF:
      handle_notification(frame);
      break;
    }
    break;
  }
  delete_frame(frame);
  free(frame);
}

void handler_eedscan(Context *ctx, uint8_t rssi[NUM_CHANNELS]) {
  printf("Channel Status:\n");
  for (int i = 0; i < NUM_CHANNELS; ++i) {
    printf("  Ch %d: %d\n", idx_to_chan(i), rssi[i]);
  }
}

void handler_epandesc(Context *ctx, Channel channel, uint8_t channel_page,
                      uint16_t pan_id, uint8_t addr[8], uint8_t lqi) {
  printf("handler_epandesc: chan=%02X, pan_id=%04X\n", channel, pan_id);
  PANAPeer *peer = (PANAPeer *)malloc(sizeof(PANAPeer));
  peer->chan = channel;
  peer->pan_id = pan_id;
  for (int i = 0; i < 8; ++i) {
    peer->mac_addr[i] = addr[i];
  }
  calculate_ipv6_from_mac_addr(addr, peer->addr);

  if (ctx->peer != NULL) {
    free(ctx->peer);
  }
  ctx->peer = peer;
}

void handler_event(Context *ctx, EventID num, uint8_t sender[16],
                   uint8_t param) {
  switch (num) {
  case NS_RECEIVED:
    printf("event: received neighbor solicitation\n");
    break;
  case NA_RECEIVED:
    printf("event: received neighbor advertisement\n");
    break;
  case ECHO_REQ_RECEIVED:
    printf("event: received echo request\n");
    break;
  case ED_SCAN_DONE:
    printf("event: ED scan finished\n");
    ctx->scan_status = NOT_SCANNING;
    break;
  case BEACON_RECEIVED:
    printf("event: beacon received\n");
    break;
  case UDP_SEND_DONE:
    switch (param) {
    case 0:
      printf("event: sending UDP packet succeeded\n");
      break;

    case 1:
      printf("event: sending UDP packet failed\n");
      break;

    case 2:
      printf("event: sending neighbor solicitation\n");
      break;

    default:
      printf("event: unknown event parameter %d\n", param);
      break;
    }
    break;

  case ACTIVE_SCAN_DONE:
    printf("event: Active scan finished\n");
    ctx->scan_status = NOT_SCANNING;
    break;

  case PANA_CONNECT_FAIL:
    printf("event: PANA session cannot be established\n");
    ctx->pana_status = NOT_CONNECTED;
    break;

  case PANA_CONNECT_DONE:
    printf("event: PANA session has been established\n");
    ctx->pana_status = CONNECTED;
    break;

  case SESSION_CLOSE_REQ:
    printf("event: received PANA session close request\n");
    break;

  case PANA_SESS_CLOSED:
    printf("event: PANA session has been closed\n");
    ctx->pana_status = NOT_CONNECTED;
    break;

  case CLOSE_REQ_TIMEOUT:
    printf("event: PANA session close request has been timed out\n");
    ctx->pana_status = NOT_CONNECTED;
    break;

  case PANA_SESS_TIMEOUT:
    printf("event: PANA session has been timed out\n");
    ctx->pana_status = NOT_CONNECTED;
    break;

  case SEND_LIMIT:
    printf("event: send rate limit activated\n");
    ctx->is_send_restricted = true;
    break;

  case SEND_LIMIT_LIFTED:
    printf("event: send rate limit is now lifted\n");
    ctx->is_send_restricted = false;
    break;

  default:
    printf("event: unknown event number %d\n", num);
    break;
  }
}

void *event_main(void *arg) {
  Context *ctx = (Context *)arg;
  char buf[256];
  while (true) {
    int ret;
    if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
      return ret;
    }
    char *cmd = strtok(buf, " ");
    if (cmd == NULL) {
      continue;
    }
    if (strcmp(cmd, "OK") == 0) {
      ctx->response = RS_OK;
    } else if (strcmp(cmd, "FAIL") == 0) {
      char *code_s = strtok(NULL, " ");
      int code;
      sprintf(code_s, "ER%2d", &code);
      ctx->response = (ResponseStatus)code;
    } else if (strcmp(cmd, "ERXUDP") == 0) {
      char *sender_s = strtok(NULL, " ");
      uint8_t sender[16];
      parse_ipv6_addr(sender_s, sender);

      char *dest_s = strtok(NULL, " ");
      uint8_t dest[16];
      parse_ipv6_addr(dest_s, dest);

      char *rport_s = strtok(NULL, " ");
      uint16_t rport = (uint16_t)strtoul(rport_s, NULL, 16);

      char *lport_s = strtok(NULL, " ");
      uint16_t lport = (uint16_t)strtoul(lport_s, NULL, 16);

      char *sender_lla_s = strtok(NULL, " ");
      uint8_t sender_lla[8];
      parse_mac_addr(sender_lla_s, sender_lla);

      char *secured_s = strtok(NULL, " ");
      bool secured = secured_s[0] == '1';

      char *data_len_s = strtok(NULL, " ");
      uint16_t data_len = (uint16_t)strtoul(data_len_s, NULL, 16);

      uint8_t *data = (uint8_t *)malloc(data_len);
      memcpy(data, data_len_s + 5, data_len);

      handler_erxudp(ctx, sender, dest, rport, lport, sender_lla, secured,
                     data_len, data);
      free(data);
    } else if (strcmp(cmd, "EEDSCAN") == 0) {
      memset(buf, 0, 256);
      if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
        return ret;
      }

      uint8_t result[NUM_CHANNELS];

      char *chan_s = strtok(buf, " ");
      uint8_t chan = (uint8_t)strtoul(chan_s, NULL, 16);
      char *rssi_s = strtok(NULL, " ");
      uint8_t rssi = (uint8_t)strtoul(rssi_s, NULL, 16);
      result[chan_to_idx(chan)] = rssi;

      for (int i = 1; i < NUM_CHANNELS; ++i) {
        chan_s = strtok(NULL, " ");
        chan = (uint8_t)strtoul(chan_s, NULL, 16);
        rssi_s = strtok(NULL, " ");
        rssi = (uint8_t)strtoul(rssi_s, NULL, 16);
        result[chan_to_idx(chan)] = rssi;
      }

      handler_eedscan(ctx, result);
    } else if (strcmp(cmd, "EVENT") == 0) {
      char *num_s = strtok(NULL, " ");
      uint8_t num = (uint8_t)strtoul(num_s, NULL, 16);

      char *sender_s = strtok(NULL, " ");
      uint8_t sender[16];
      parse_ipv6_addr(sender_s, sender);

      char *param_s = strtok(NULL, " ");
      uint8_t param = 0;
      if (param_s != NULL) {
        param = (uint8_t)strtoul(param_s, NULL, 16);
      }

      handler_event(ctx, num, sender, param);
    } else if (strcmp(cmd, "EPANDESC") == 0) {
      memset(buf, 0, 256);
      if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
        return ret;
      }
      uint8_t channel;
      sscanf(buf, "  Channel:%2X", &channel);

      if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
        return ret;
      }
      uint8_t channel_page;
      sscanf(buf, "  Channel Page:%2X", &channel_page);

      if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
        return ret;
      }
      unsigned int pan_id;
      sscanf(buf, "  Pan ID:%4X", &pan_id);

      if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
        return ret;
      }
      char addr_s[17];
      sscanf(buf, "  Addr:%s", &addr_s);
      uint8_t addr[8];
      parse_mac_addr(addr_s, addr);

      if ((ret = read_serial(ctx->fd, buf, 256)) < 0) {
        return ret;
      }
      unsigned int lqi;
      sscanf(buf, "  LQI:%2X", &lqi);

      handler_epandesc(ctx, (Channel)channel, channel_page, (uint16_t)pan_id,
                       addr, (uint8_t)lqi);
    } else {
      // no handler
    }
  }
}

int broute_main(int argc, char *argv[]) {
  boardctl(BOARDIOC_INIT, 0);

  /*
  if (argc == 1) {
    printf("%s [UART Dev]\n", argv[0]);
    return 0;
  }
  */

  // 1 msec.
  const struct timespec sleep_wait = {0, 1000 * 1000};

  // interval for fetching current energy.
  const struct timespec fetch_interval = {60, 0};

#include "broute_secrets.h"
  printf("main: auth info: id = %s\n", rbid);
  printf("main: auth info: pw = %s\n", rbpw);

  // char *dev = argv[1];
  const char *dev = "/dev/ttyS2";
  int fd = open(dev, O_RDWR | O_NOCTTY);
  if (fd < 0) {
    perror("main: failed to open device");
    return -1;
  }

  // we need wait for 3 seconds before publish the first command.
  // see BP35A1 data sheet.
  printf("main: waiting for starting up...\n");
  sleep(3);

  bp35a1 *client = bp35a1_init(fd);
  if (client == NULL) {
    printf("failed to initialize\n");
    return -1;
  }
  Context *ctx = context_new();
  ctx->fd = fd;

  printf("main: hello, B-route :)\n");

  int ret;
  /*
  char buf[128];
  ret = bp35a1_version(client, buf);
  if (ret < 0) {
    printf("main: failed to get firmware version (%d)\n", ret);
    bp35a1_close(client);
    return 1;
  }
  printf("main: firmware version = %s\n", buf);
  */
  ResponseStatus response;

  printf("main: set auth info\n");
  if ((ret = bp35a1_auth_init(client, rbid, rbpw)) < 0) {
    printf("main: auth init failed (code=%d, errno=%d)\n", ret, errno);
    bp35a1_close(client);
    return -1;
  }

  printf("main: creating event loop thread\n");
  pthread_t ptid;
  if (pthread_create(&ptid, NULL, event_main, ctx)) {
    perror("main: create event thread");
    bp35a1_close(client);
    return -1;
  }

  printf("main: starting active scan\n");
  for (int i = 0; i < 5; ++i) {
    if ((ret = bp35a1_start_active_scan(client, 6)) < 0) {
      printf("main: failed to start scan (ret=%d, errno=%d)\n", ret, errno);
      bp35a1_close(client);
      return -1;
    }
    ctx->scan_status = ACTIVE_SCAN;

    while (ctx->scan_status != NOT_SCANNING) {
      nanosleep(&sleep_wait, NULL);
    }

    if (ctx->peer != NULL) {
      break;
    }
    printf("main: no peer found. retrying (%d/%d)\n", i + 1, 5);
  }

  if (ctx->peer == NULL) {
    printf("main: no peer found\n");
    bp35a1_close(client);
    return -1;
  }

  printf("main: found PAN:\n");
  printf("  ");
  print_peer_info(ctx->peer);

  printf("main: set channel to %02X\n", ctx->peer->chan);
  if ((ret = bp35a1_set_channel(client, ctx->peer->chan)) < 0) {
    printf("main: failed to set channel (ret=%d, errno=%d)\n", ret, errno);
    bp35a1_close(client);
    return -1;
  }
  response = context_wait_response(ctx, 10);
  if (response == RS_NO_RESPONSE) {
    printf("main: set channel timed out\n");
    bp35a1_close(client);
    return -1;
  }
  if (response != RS_OK) {
    printf("main: set channel failed (code=%d)\n", response);
    bp35a1_close(client);
    return -1;
  }

  printf("main: set PAN ID to %04X\n", ctx->peer->pan_id);
  if ((ret = bp35a1_set_pan_id(client, ctx->peer->pan_id)) < 0) {
    printf("main: failed to set PAN ID (ret=%d, errno=%d)\n", ret, errno);
    bp35a1_close(client);
    return -1;
  }
  response = context_wait_response(ctx, 10);
  if (response == RS_NO_RESPONSE) {
    printf("main: set PAN ID timed out\n");
    bp35a1_close(client);
    return -1;
  }
  if (response != RS_OK) {
    printf("main: set PAN ID failed (code=%d)\n", response);
    bp35a1_close(client);
    return -1;
  }

  char addr[40] = {};
  str_ipv6_addr(addr, ctx->peer->addr);
  printf("main: try to join to %s\n", addr);
  if ((ret = bp35a1_join(client, addr)) < 0) {
    printf("main: join failed (ret=%d, errno=%d)\n", ret, errno);
    bp35a1_close(client);
    return -1;
  }
  ctx->pana_status = CONNECTING;

  printf("main: waiting for establishing connection\n");
  for (int i = 0; i < 10000; ++i) {
    if (ctx->pana_status == NOT_CONNECTED) {
      printf("main: connection attempt failed\n");
      bp35a1_close(client);
      return -1;
    } else if (ctx->pana_status == CONNECTED) {
      printf("main: connected\n");
      break;
    }
    nanosleep(&sleep_wait, NULL);
  }

  if (ctx->pana_status != CONNECTED) {
    printf("main: connection status should be CONNECTED, but %d\n",
           ctx->pana_status);
    bp35a1_close(client);
    return -1;
  }

  EOJ sender = {0x05, 0xFF, 0x01};
  EOJ dest = {0x02, 0x88, 0x01};

  ELDefiendData edata;
  edata.sender = sender;
  edata.dest = dest;
  edata.esv = 0x62;
  edata.opc = 2;
  edata.properties = (ELProperty **)malloc(sizeof(ELProperty *) * edata.opc);
  edata.properties[0] = (ELProperty *)malloc(sizeof(ELProperty));
  edata.properties[0]->epc = ELHPC_MEASURED_INST_EN;
  edata.properties[0]->pdc = 0x00;
  edata.properties[0]->edt = NULL;
  edata.properties[1] = (ELProperty *)malloc(sizeof(ELProperty));
  edata.properties[1]->epc = ELHPC_MEASURED_INST_CR;
  edata.properties[1]->pdc = 0x00;
  edata.properties[1]->edt = NULL;
  EDATA data;
  data.defined = &edata;

  srand(time(NULL));
  uint16_t tid = (uint16_t)rand();
  while (true) {
    printf("main: making frame with tid=%d\n", tid);
    ELFrame *frame = make_frame(DEFINED_FORM, tid, data);
    uint8_t *packed;
    size_t plen = pack_frame(frame, &packed);
    printf("main: sending request\n");
    printf("main: payload (%d bytes) =", plen);
    for (size_t i = 0; i < plen; ++i) {
      printf(" %02X", packed[i]);
    }
    printf("\n");
    if ((ret = bp35a1_sendto(client, 1, addr, EL_PORT, true, plen, packed)) <
        0) {
      printf("main: failed to send UDP packet (%d)\n", ret);
      bp35a1_close(client);
      break;
    }
    context_begin_transaction(ctx, tid, handle_measured_inst_res);
    ++tid;
    nanosleep(&fetch_interval, NULL);
  }

  context_delete(ctx);
  printf("brm: finish\n");
  return 0;
}
