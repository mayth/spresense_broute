#ifndef __ECHONET_LITE_H__
#define __ECHONET_LITE_H__

#include <sys/types.h>

/// ECHONET Lite Header 1 (EHD1).
static const uint8_t EHD1 = 16; // 0b00010000

static const uint16_t EL_PORT = 3610;

typedef enum { DEFINED_FORM = 0x81, ARBITRARY_FORM = 0x82 } EDATAForm;

typedef enum {
  ELCG_SENSOR = 0x00,
  ELCG_AIR_CONDITIONER = 0x01,
  ELCG_HOME_FACILITY = 0x02,
  ELCG_COOCKING_HOUSEWORK = 0x03,
  ELCG_HEALTH = 0x04,
  ELCG_MANAGEMENT_CONTROL = 0x04,
  ELCG_AV = 0x05,
  ELCG_PROFILE = 0x0E,
  ELCG_USER_DEFINED = 0x0F
} ClassGroupCodes;

typedef enum {
  /// Property write request (no response required).
  ESV_SET_I = 0x60,
  /// Property write request (response required).
  ESV_SET_C = 0x61,
  /// Property read request.
  ESV_GET = 0x62,
  /// Property notification request.
  ESV_INF_REQ = 0x63,
  /// Property write & read request.
  ESV_SET_GET = 0x6E,

  /// Property write response.
  ESV_SET_RES = 0x71,
  /// Property read response.
  ESV_GET_RES = 0x72,
  /// Property notification.
  ESV_INF = 0x73,
  /// Property notification (response required).
  ESV_INFC = 0x74,
  /// Property notification response (response for ESV_INFC).
  ESV_INFC_RES = 0x7A,
  /// Property write & read response.
  ESV_SET_GET_RES = 0x7E,

  /// Property is not available for write.
  ESV_SETI_SNA = 0x50,
  /// Property is not available for write.
  ESV_SETC_SNA = 0x51,
  /// Property is not available for read.
  ESV_GET_SNA = 0x52,
  /// Property is not available for notification.
  ESV_INF_SNA = 0x53,
  /// Property is not available for write & read.
  ESV_SET_GET_SNA = 0x5E,
} ELService;

typedef enum {
  /// Measured instantaneous electric energy.
  ELHPC_MEASURED_INST_EN = 0xE7,
  /// Measured instantaneous currents.
  ELHPC_MEASURED_INST_CR = 0xE8,
  /// Cumulative amounts of electric energy measured at fixed time
  /// (normal direction).
  ELHPC_FIXED_CUMULATIVE_AMT = 0xEA,
  /// Cumulative amounts of electric energy measured at fixed time
  /// (reverse direction).
  ELHPC_FIXED_CUMULATIVE_AMT_REV = 0xEB
} ELHEMSPropertyCode;

typedef enum {
  /// Notification of instance list.
  NPPC_INST_LIST = 0xD5
} NodeProfileClassPropertyCode;

typedef struct {
  uint8_t class_group_code;
  uint8_t class_code;
  uint8_t instance_code;
} EOJ;

typedef struct {
  /// ECHONET Lite property specifier.
  uint8_t epc;
  /// A length of EDT in bytes.
  uint8_t pdc;
  /// Property value.
  uint8_t *edt;
} ELProperty;

typedef struct {
  /// EOJ of sender.
  EOJ sender;
  /// EOJ of destination.
  EOJ dest;
  /// ECHONET Lite service specifier.
  uint8_t esv;
  /// A number of properties.
  uint8_t opc;
  /// ECHONET Lite properties.
  ELProperty **properties;
} ELDefiendData;

typedef union {
  ELDefiendData *defined;
  struct {
    size_t size;
    uint8_t *data;
  } arbitrary_data;
} EDATA;

typedef struct {
  uint8_t ehd1;
  uint8_t ehd2;
  /// Transaction ID.
  uint16_t tid;
  EDATA edata;
} ELFrame;

typedef enum {
  /// Invalid frame.
  EEFRAMEINVAL = -1
} ELError;

ELFrame *make_frame(EDATAForm form, uint16_t tid, EDATA data);
void delete_frame(ELFrame *frame);

int parse_frame(const uint8_t *data, size_t len, ELFrame *frame);
int parse_edata(const uint8_t *data, ELDefiendData *edata);
int parse_props(const uint8_t *data, ELDefiendData *edata);
void delete_props(ELDefiendData *edata);

size_t pack_frame(const ELFrame *frame, uint8_t **packed_frame);

#endif