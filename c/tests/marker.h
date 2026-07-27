
#ifndef THIRDEYE_TEST_MARKER_H
#define THIRDEYE_TEST_MARKER_H

#include <windows.h>

static const COLORREF kMarkerQuad[4] = {
    RGB(0xFF, 0x00, 0x00),  
    RGB(0x00, 0xFF, 0x00),  
    RGB(0x00, 0x00, 0xFF),  
    RGB(0xFF, 0xFF, 0x00),  
};

static const char* kMarkerNames[4] = { "red", "green", "blue", "yellow" };

static const int kMarkerBoxSize = 128;
static const int kMarkerBorder  = 8;

#endif
