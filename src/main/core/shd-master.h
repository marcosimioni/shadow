/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#ifndef SHD_ENGINE_H_
#define SHD_ENGINE_H_

#include <glib.h>

typedef struct _Master Master;

Master* master_new(Options*);
gint master_free(Master*);
void master_run(Master*);

void master_updateMinTimeJump(Master*, gdouble);
GTimer* master_getRunTimer(Master*);

gboolean master_slaveFinishedCurrentRound(Master*, SimulationTime, SimulationTime*, SimulationTime*);
gdouble master_getLatency(Master* master, Address* srcAddress, Address* dstAddress);

// TODO remove these eventually since they cant be shared accross remote slaves
DNS* master_getDNS(Master* master);
Topology* master_getTopology(Master* master);

#endif /* SHD_ENGINE_H_ */
