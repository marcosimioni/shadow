/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

#include "main/utility/pcap_writer.h"

#include <stdio.h>

#include "lib/logger/logger.h"
#include "main/core/support/definitions.h"
#include "main/core/worker.h"
#include "main/host/host.h"

struct _PCapWriter {
    FILE *pcapFile;
    FILE *csvFile;
};

static void _pcapwriter_writeHeader(PCapWriter* pcap) {
    fprintf(pcap->csvFile, "timestamp,sourceIP,sourcePort,destIP,destPort,tcpSequence,tcpFlags,payloadLength\n");
}

void pcapwriter_writePacket(PCapWriter* pcap, PCapPacket* packet) {
    if(!pcap || !pcap->pcapFile || !packet) {
        return;
    }

    guint32 ts_sec;         /* timestamp seconds */
    guint32 ts_usec;        /* timestamp microseconds */
    guint32 incl_len;       /* number of octets of packet saved in file */
    guint32 orig_len;       /* actual length of packet */

    /* get the current time that the packet is being sent/received */
    SimulationTime now = worker_getCurrentTime();
    ts_sec = now / SIMTIME_ONE_SECOND;
    ts_usec = (now % SIMTIME_ONE_SECOND) / SIMTIME_ONE_MICROSECOND;

    if(!pcap || !pcap->csvFile || !packet) {
        return;
    }

    guint8 tcpFlags = 0;
    if(packet->rstFlag) tcpFlags |= 0x04;
    if(packet->synFlag) tcpFlags |= 0x02;
    if(packet->ackFlag) tcpFlags |= 0x10;
    if(packet->finFlag) tcpFlags |= 0x01;

    /* write to CSV too */
    fprintf(pcap->csvFile, "%d.%06d,%s,%d,%s,%d,%d,%d,%d\n",
      ts_sec,
      ts_usec,
      address_ipToNewString(packet->srcIP),
      ntohs(packet->srcPort),
      address_ipToNewString(packet->dstIP),
      ntohs(packet->dstPort),
      packet->seq,
      tcpFlags,
      packet->payloadLength);
}

PCapWriter* pcapwriter_new(Host* host, gchar* pcapDirectory, gchar* pcapFilename) {
    PCapWriter* pcap = g_new0(PCapWriter, 1);

    /* open the PCAP file for writing */
    GString *filename = g_string_new("");
    if (pcapDirectory) {
        g_string_append(filename, pcapDirectory);
        /* Append trailing slash if not present */
        if (!g_str_has_suffix(pcapDirectory, "/")) {
            g_string_append(filename, "/");
        }
    } else {
        /* Use default directory */
        g_string_append(filename, "data/pcapdata/");
    }

    if(pcapFilename) {
        g_string_append_printf(filename, "%s", pcapFilename);
    } else {
        g_string_append_printf(filename, "%s", host_getName(host));
    }

    if (!g_str_has_suffix(filename->str, ".pcap")) {
        g_string_append(filename, ".pcap");
    }

    pcap->pcapFile = fopen(filename->str, "w");
    if(!pcap->pcapFile) {
        warning("error trying to open PCAP file '%s' for writing", filename->str);
    }

    if (!g_str_has_suffix(filename->str, ".csv")) {
        g_string_append(filename, ".csv");
    }

    pcap->csvFile = fopen(filename->str, "w");
    if(!pcap->csvFile) {
        warning("error trying to open CSV file '%s' for writing", filename->str);
    }

    if(pcap->pcapFile && pcap->csvFile) {
        _pcapwriter_writeHeader(pcap);
    }

    return pcap;
}

void pcapwriter_free(PCapWriter* pcap) {
    if(pcap && pcap->pcapFile) {
        fclose(pcap->pcapFile);
    }
    if(pcap && pcap->csvFile) {
        fclose(pcap->csvFile);
    }
}
