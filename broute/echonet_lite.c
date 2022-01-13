#include "echonet_lite.h"

#include <stdlib.h>
#include <string.h>

ELFrame *make_frame(EDATAForm form, uint16_t tid, EDATA data) {
  ELFrame *frame = (ELFrame *)malloc(sizeof(ELFrame));
  frame->ehd1 = EHD1;
  frame->ehd2 = form;
  frame->tid = tid;
  frame->edata = data;
  return frame;
}

void delete_frame(ELFrame *frame) {
  switch (frame->ehd2) {
  case ARBITRARY_FORM:
    free(frame->edata.arbitrary_data.data);
    frame->edata.arbitrary_data.data = NULL;
    frame->edata.arbitrary_data.size = 0;
    break;
  case DEFINED_FORM:
    free(frame->edata.defined);
    frame->edata.defined = NULL;
  default:
    break;
  }
}

int parse_frame(const uint8_t *data, size_t len, ELFrame *frame) {
  frame->ehd1 = data[0];
  if (frame->ehd1 != EHD1) {
    return EEFRAMEINVAL;
  }
  frame->ehd2 = data[1];
  frame->tid = ((uint16_t)data[2] << 8) | data[3];
  switch (frame->ehd2) {
  case ARBITRARY_FORM:
    frame->edata.arbitrary_data.size = len - 4;
    frame->edata.arbitrary_data.data = malloc(len - 4);
    memcpy(frame->edata.arbitrary_data.data, data + 4, len - 4);
    break;
  case DEFINED_FORM:
    frame->edata.defined = malloc(sizeof(ELDefiendData));
    int ret = parse_edata(data + 4, frame->edata.defined);
    if (ret < 0) {
      return ret;
    }
    break;
  default:
    break;
  }
  return OK;
}

int parse_edata(const uint8_t *data, ELDefiendData *edata) {
  int pos = 0;
  memcpy(&edata->sender, data + pos, 3);
  pos += 3;
  memcpy(&edata->dest, data + pos, 3);
  pos += 3;
  edata->esv = data[pos++];
  edata->opc = data[pos++];
  if (edata->opc == 0) {
    edata->properties = NULL;
  } else {
    edata->properties = malloc(sizeof(ELProperty *) * edata->opc);
    for (int i = 0; i < edata->opc; ++i) {
      ELProperty *prop = malloc(sizeof(ELProperty));
      prop->epc = data[pos++];
      prop->pdc = data[pos++];
      prop->edt = malloc(prop->pdc);
      memcpy(prop->edt, data + pos, prop->pdc);
      pos += prop->pdc;
      edata->properties[i] = prop;
    }
  }
  return OK;
}

void delete_props(ELDefiendData *edata) {
  for (int i = 0; i < edata->opc; ++i) {
    free(edata->properties[i]->edt);
    edata->properties[i]->edt = NULL;
    free(edata->properties[i]);
    edata->properties[i] = NULL;
  }
  free(edata->properties);
  edata->properties = NULL;
}

static size_t calc_packed_len(const ELFrame *frame) {
  size_t len = 4;
  switch (frame->ehd2) {
  case ARBITRARY_FORM:
    len += frame->edata.arbitrary_data.size;
    break;
  case DEFINED_FORM:
    len += 8;
    for (int i = 0; i < frame->edata.defined->opc; ++i) {
      len += 2 + frame->edata.defined->properties[i]->pdc;
    }
  default:
    break;
  }
  return len;
}

size_t pack_frame(const ELFrame *frame, uint8_t **packed_frame) {
  size_t len = calc_packed_len(frame);
  uint8_t *data = (uint8_t *)malloc(len);
  int pos = 0;
  data[pos++] = frame->ehd1;
  data[pos++] = frame->ehd2;
  // memcpy(data + pos, &frame->tid, 2);
  data[pos++] = (uint8_t)(frame->tid >> 8);
  data[pos++] = (uint8_t)(frame->tid & 0xFF);
  switch (frame->ehd2) {
  case ARBITRARY_FORM:
    memcpy(data + pos, frame->edata.arbitrary_data.data,
           frame->edata.arbitrary_data.size);
    break;
  case DEFINED_FORM: {
    ELDefiendData *edata = frame->edata.defined;
    memcpy(data + pos, &edata->sender, sizeof(EOJ));
    pos += sizeof(EOJ);
    memcpy(data + pos, &edata->dest, sizeof(EOJ));
    pos += sizeof(EOJ);
    data[pos++] = edata->esv;
    data[pos++] = edata->opc;
    for (int i = 0; i < edata->opc; ++i) {
      ELProperty *prop = edata->properties[i];
      data[pos++] = prop->epc;
      data[pos++] = prop->pdc;
      if (prop->pdc > 0) {
        memcpy(data + pos, prop->edt, prop->pdc);
        pos += prop->pdc;
      }
    }
    break;
  }
  }
  *packed_frame = data;
  return len;
}
