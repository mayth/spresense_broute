#ifndef __BP35A1_H__
#define __BP35A1_H__

#include <stdbool.h>
#include <sys/types.h>

/***** Public Data *****/
typedef struct {
  int fd;
} bp35a1;

typedef struct {
  int channel;
  int channel_page;
  char *pan_id;
  char *addr;
  int lqi;
} epandesc;

/// I/O error.
#define BP35A1_EIO      (-2)
/// Command not found.
#define BP35A1_ENOCMD   (-3)
/// Command execution failure.
#define BP35A1_ECMDFAIL (-4)
#define BP35A1_EARG     (-5)

/// Initializes a new client.
bp35a1 *bp35a1_init(int fd);

/// Closes a client.
void bp35a1_close(bp35a1 *client);

/// Gets a firmware version.
int bp35a1_version(bp35a1 *client, char *buf);

int bp35a1_start_active_scan(bp35a1 *client, uint8_t duration);
int bp35a1_start_ed_scan(bp35a1 *client, uint8_t duration);

int bp35a1_set_channel(bp35a1 *client, uint8_t chan);
int bp35a1_set_pan_id(bp35a1 *client, uint16_t pan_id);

/// Prepares authorization information.
int bp35a1_auth_init(bp35a1 *client, const char *rbid, const char *pwd);

/// Connects to the `addr`.
int bp35a1_join(bp35a1 *client, const char *addr);

int bp35a1_sendto(bp35a1 *client, uint8_t handle, const char *addr,
                  uint16_t port, bool sec, size_t len, const uint8_t *data);

#endif