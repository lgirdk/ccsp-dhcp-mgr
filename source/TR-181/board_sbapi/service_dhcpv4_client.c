/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include "sysevent/sysevent.h"
#include "syscfg/syscfg.h"
#include "util.h"
#include "errno.h"
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/time.h>
#include "safec_lib_common.h"
#include "service_dhcpv4_client.h"
#include "ccsp_trace.h"
#include "cosa_apis.h"


#define BUFF_LEN_8      8
#define BUFF_LEN_16     16
#define BUFF_LEN_32     32
#define BUFF_LEN_64     64
#define BUFF_LEN_128    128
#define BUFF_LEN_256    256

#define SERVICE_NAME            "dhcpv4_client"
#define DHCPV4_REGISTER_FILE    "/tmp/dhcpv4_registered_events"
#define VENDOR_SPEC_FILE        "/etc/udhcpc.vendor_specific"
#define VENDOR_OPTIONS_LENGTH   100
#define MAX_EVENTS              6
#define PROG_NAME               "DHCPV4_CLIENT"

#define EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED         72003001
#define EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED_STR     "eRouter is administratively disabled"

/**********************************************************************
        VARIABLE DECLARATIONS
**********************************************************************/
char  DHCPC_PID_FILE[BUFF_LEN_128] = "";
FILE* g_fArmConsoleLog = NULL;

static async_id_t   l_sAsyncID[MAX_EVENTS];
static pthread_t    sysevent_tid;

serv_dhcp *sd;

/**********************************************************************
        FUNCTION DECLARATIONS
**********************************************************************/
static int serv_dhcp_deinit();
static void *dhcpv4_client_sysevent_handler(void *sd_arg);


#if defined (_XB6_PRODUCT_REQ_) || defined(_CBR_PRODUCT_REQ_) || defined (_XB7_PRODUCT_REQ_)
#define CONSOLE_LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
#define CONSOLE_LOG_FILE "/rdklogs/logs/ArmConsolelog.txt.0"
#endif


/**********************************************************************
    function:
        get_dhcpc_pidfile
    description:
        This function is to get the pid of dhcpv4 client process.
    argument:
        char    *pidfile,
        int     size
    return:
        0  if success
        -1 if error
**********************************************************************/
int get_dhcpc_pidfile
(
    char *pidfile,
    int size
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    #if defined(_PLATFORM_IPQ_)
        strncpy(pidfile,"/tmp/udhcpc.erouter0.pid",size);

    #elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
    {
        char udhcpflag[BUFF_LEN_16]="";
        syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
        if( 0 == strcmp(udhcpflag,"true"))
        {
            strncpy(pidfile,"/tmp/udhcpc.erouter0.pid",size);
        }
        else
        {
            strncpy(pidfile,"/var/run/eRT_ti_udhcpc.pid",size);
        }
    }
    #else
        strncpy(pidfile,"/tmp/udhcpc.erouter0.pid",size);
    #endif
    return 0;
}

/**********************************************************************
    function:
        dhcp_parse_vendor_info
    description:
        This function is to parse the vendor info from Vendorinfo file.
    argument:
        char         *options,
        const int    length,
        char         *ethWanMode
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcp_parse_vendor_info
(
    char       *options,
    const int  length,
    char       *ethWanMode
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    FILE *fp;
    char subopt_num[BUFF_LEN_16] ={0}, subopt_value[BUFF_LEN_64] = {0}, mode[BUFF_LEN_8] = {0};
    int num_read;
    errno_t rc = -1;

    if ((fp = fopen(VENDOR_SPEC_FILE, "ra")) != NULL)
    {
        int opt_len = 0;   //Total characters read

        //Start the string off with "43:"
        rc =  sprintf_s(options, length, "43:");
        if(rc < EOK)
        {
           ERR_CHK(rc);
        }
        opt_len = rc;

        while ((num_read = fscanf(fp, "%7s %11s %63s", mode, subopt_num, subopt_value)) == 3)
        {
            char *ptr;
            if (length - opt_len < 6)
            {
                CcspTraceInfo(("%s: Too many options\n", __FUNCTION__));
                fclose(fp);   // Resource leak
                return -1;
            }

            #if defined (EROUTER_DHCP_OPTION_MTA)
                if ((strcmp(mode,"DOCSIS") == 0) && (strcmp(ethWanMode,"true") == 0))
                {
                    CcspTraceInfo(("DOCSIS Mode\n"));
                    continue;
                }

                if ((strcmp(mode,"ETHWAN") == 0) && (strcmp(ethWanMode,"false") == 0))
                {
                    CcspTraceInfo(("EWAN Mode\n"));
                    continue;
                }
            #else
                UNREFERENCED_PARAMETER(ethWanMode);
                if ((strcmp(mode,"ETHWAN") == 0 ))
                {
                    CcspTraceInfo(("EWAN Mode\n"));
                    continue;
                }
            #endif

            //Print the option number
            if (strcmp(subopt_num, "SUBOPTION2") == 0)
            {
                rc = sprintf_s(options + opt_len, (length - opt_len), "02");
                if(rc < EOK)
                {
                   ERR_CHK(rc);
                }
                opt_len += rc;
            }
            else if (strcmp(subopt_num, "SUBOPTION3") == 0)
            {
                rc = sprintf_s(options + opt_len, (length - opt_len), "03");
                if(rc < EOK)
                {
                   ERR_CHK(rc);
                }
                opt_len += rc;
            }
            else
            {
                CcspTraceError(("%s: Invalid suboption\n", __FUNCTION__));
                fclose(fp);
                return -1;
            }

            //Print the length of the sub-option value
            rc = sprintf_s(options + opt_len, (length - opt_len), "%02x", strlen(subopt_value));
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            opt_len += rc;

            //Print the sub-option value in hex
            for (ptr=subopt_value; (char)*ptr != (char)0; ptr++)
            {
                if (length - opt_len <= 2)
                {
                    CcspTraceInfo(("%s: Too many options\n", __FUNCTION__));
                    fclose(fp);
                    return -1;
                }
                rc = sprintf_s(options + opt_len, (length - opt_len), "%02x", *ptr);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
                opt_len += rc;
            }
        } //while

        if ((num_read != EOF) && (num_read != 3))
        {
            CcspTraceError(("%s: Error parsing file\n", __FUNCTION__));
            fclose(fp);
            return -1;
        }
    }
    else
    {
        CcspTraceError(("%s: Cannot read %s\n", __FUNCTION__, VENDOR_SPEC_FILE));
        return -1;
    }
    fclose(fp);
    return 0;
}

/**********************************************************************
    function:
        serv_dhcp_init
    description:
        This function is to initialize service dhcp structure.
    argument:
        NONE
    return:
        0  if success
        -1 if error
**********************************************************************/
int serv_dhcp_init()
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    char buf[BUFF_LEN_32];
    memset(buf,0,sizeof(buf));

    if(sd == NULL)
    {
        sd = (serv_dhcp *)malloc(sizeof(serv_dhcp));
        if (sd == NULL)
        {
            CcspTraceError(("Malloc failed\n"));
            return -1;
        }
    }
    if ((sd->sefd = sysevent_open(SE_SERV, SE_SERVER_WELL_KNOWN_PORT,
                    SE_VERSION, PROG_NAME, &sd->setok)) < 0)
    {
        CcspTraceError(("Failed to open sysevent, Call serv_dhcp_deinit\n"));
        serv_dhcp_deinit();
        return -1;
    }

    syscfg_get(NULL, "wan_physical_ifname", sd->ifname, sizeof(sd->ifname));
    if (!strlen(sd->ifname))
    {
        CcspTraceError(("Failed to get ifname. Call serv_dhcp_deinit\n"));
        serv_dhcp_deinit();
        return -1;
    }

    syscfg_get(NULL, "wan_proto", buf, sizeof(buf));
    if (strcasecmp(buf, "dhcp") == 0)
    {
        sd->prot = PROT_DHCP;
    }
    else if (strcasecmp(buf, "static") == 0)
    {
        sd->prot = PROT_STATIC;
    }
    else
    {
        CcspTraceError(("Failed to get wan protocol. Call serv_dhcp_deinit\n"));
        serv_dhcp_deinit();
        return -1;
    }

    memset(buf,0,sizeof(buf));

    syscfg_get(NULL, "last_erouter_mode", buf, sizeof(buf));
    CcspTraceInfo(("Last erouter mode = %s \n", buf));
    switch (atoi(buf))
    {
        case 1:
            sd->rtmod = RTMOD_IPV4;
            break;
        case 2:
            sd->rtmod = RTMOD_IPV6;
            break;
        case 3:
            sd->rtmod = RTMOD_DS;
            break;
        default:
            CcspTraceError(("Unknown RT mode (last_erouter_mode)\n"));
            sd->rtmod = RTMOD_UNKNOW;
            break;
    }

    // Sysevent handler thread creation
    CcspTraceInfo(("Create sysevent handler thread \n"));
    pthread_create(&sysevent_tid, NULL, dhcpv4_client_sysevent_handler, (void*)sd);
    return 0;
}

/**********************************************************************
    function:
        serv_dhcp_deinit
    description:
        This function is to deinitialize service dhcp structure.
    argument:
        NONE
    return:
        0  if success
        -1 if error
**********************************************************************/
static int serv_dhcp_deinit()
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    sysevent_close(sd->sefd, sd->setok);
    if(sd != NULL)
    {
        free(sd);
        sd = NULL;
    }
    return 0;
}

/**********************************************************************
    function:
        dhcpv4_client_service_start
    description:
        This function is called to trigger the start of dhcpv4 client process.
    argument:
        serv_dhcp *sd
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_service_start(serv_dhcp *sd)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    int pid;
    int has_pid_file = 0;
    #if defined(_PLATFORM_IPQ_)
        int ret = -1;
    #endif

    //serv_dhcp_init(sd);

    #if defined(_PLATFORM_IPQ_)
        pid = pid_of("udhcpc", sd->ifname);
    #elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
    {
        char udhcpflag[BUFF_LEN_16]="";
        syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
        if( 0 == strcmp(udhcpflag,"true"))
        {
            pid = pid_of("udhcpc", sd->ifname);
        }
        else
        {
            pid = pid_of("ti_udhcpc", sd->ifname);
        }
    }
    #else
            pid = pid_of("udhcpc", sd->ifname);
    #endif

    get_dhcpc_pidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if (access(DHCPC_PID_FILE, F_OK) == 0)
    {
        has_pid_file = 1;
    }

    if (pid > 0 && has_pid_file)
    {
        CcspTraceInfo(("%s: DHCP client has already running as PID %d\n", __FUNCTION__, pid));
        return 0;
    }

    if (pid > 0 && !has_pid_file)
    {
        kill(pid, SIGKILL);
    }
    else if (pid <= 0 && has_pid_file)
    {
        CcspTraceInfo(("Has Pid file, Stop dhcpv4 client \n"));
        dhcpv4_client_stop(sd->ifname);
    }

    #if defined(_PLATFORM_IPQ_)
        /*
         * Setting few sysevent parameters which were previously getting set
         * in Gateway provisioning App. This is done to save the delay
         * in configuration and to support WAN restart functionality.
         */
        if ( 0 != (ret = dhcpv4_client_start(sd)) )
        {
            CcspTraceError(("Dhcpv4 client start Failure \n"));
            return ret;
        }

        system("sysevent set current_ipv4_link_state up");
        system("sysevent set ipv4_wan_ipaddr `ifconfig erouter0 \
                       | grep \"inet addr\" | cut -d':' -f2 | awk '{print$1}'`");
        system("sysevent set ipv4_wan_subnet `ifconfig erouter0 \
                       | grep \"inet addr\" | cut -d':' -f4 | awk '{print$1}'`");
        return 0;
    #else
        return dhcpv4_client_start(sd);
    #endif
}

/**********************************************************************
    function:
        dhcpv4_client_service_stop
    description:
        This function is to trigger the stop of dhcpv4 client process.
    argument:
        serv_dhcp *sd
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_service_stop
(
    serv_dhcp *sd
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    return dhcpv4_client_stop(sd->ifname);
}

/**********************************************************************
    function:
        dhcpv4_client_service_restart
    description:
        This function is to restart the dhcpv4 client process.
    argument:
        serv_dhcp *sd
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_service_restart
(
    serv_dhcp *sd
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    if (dhcpv4_client_stop(sd->ifname) != 0)
    {
        CcspTraceError(("DHCPv4 stop error \n"));
    }

    return dhcpv4_client_start(sd);
}

/**********************************************************************
    function:
        dhcpv4_client_service_renew
    description:
        This function is to renew the dhcpv4 ip.
    argument:
        serv_dhcp *sd
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_service_renew
(
    serv_dhcp *sd
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    FILE *fp;
    char pid[BUFF_LEN_16];
    char line[BUFF_LEN_64], *cp;

    get_dhcpc_pidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if ((fp = fopen(DHCPC_PID_FILE, "rb")) == NULL)
    {
        CcspTraceInfo(("Call dhcpv4 start \n"));
        return dhcpv4_client_start(sd);
    }

    if (fgets(pid, sizeof(pid), fp) != NULL && atoi(pid) > 0)
    {
        kill(atoi(pid), SIGUSR1); // triger DHCP release
    }

    fclose(fp);
    sysevent_set(sd->sefd, sd->setok, "current_wan_state", "up", 0);

    if ((fp = fopen("/proc/uptime", "rb")) == NULL)
    {
        return -1;
    }
    if (fgets(line, sizeof(line), fp) != NULL)
	{
        if ((cp = strchr(line, '.')) != NULL)
        {
            *cp = '\0';
        }
        sysevent_set(sd->sefd, sd->setok, "wan_start_time", line, 0);
    }
    fclose(fp);
    return 0;
}

/**********************************************************************
    function:
        dhcpv4_client_service_release
    description:
        This function is called to trigger dhcp release.
    argument:
        serv_dhcp *sd
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_service_release
(
    serv_dhcp *sd
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    FILE *fp;
    char pid[BUFF_LEN_16];

    get_dhcpc_pidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if ((fp = fopen(DHCPC_PID_FILE, "rb")) == NULL)
    {
        CcspTraceError(("Fopen failure \n"));
        return -1;
    }

    if (fgets(pid, sizeof(pid), fp) != NULL && atoi(pid) > 0)
    {
        CcspTraceInfo(("Trigger DHCP release \n"));
        kill(atoi(pid), SIGUSR2); // triger DHCP release
    }

    fclose(fp);

    vsystem("ip -4 addr flush dev %s", sd->ifname);
    return 0;
}

/**********************************************************************
    function:
        dhcpv4_client_sysevent_handler
    description:
        This function is to handle the sysevents.
    argument:
        void *sd_arg
    return:
        0  if success
        -1 if error
**********************************************************************/
static void *dhcpv4_client_sysevent_handler
(
    void *sd_arg
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    sd = (serv_dhcp*)sd_arg;

    sd->sefd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "dhcpv4_client_handler", &sd->setok);
    sysevent_set_options(sd->sefd, sd->setok, "dhcp_client-start", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sd->sefd, sd->setok, "dhcp_client-start", &l_sAsyncID[0]);
    sysevent_set_options(sd->sefd, sd->setok, "dhcp_client-stop", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sd->sefd, sd->setok, "dhcp_client-stop", &l_sAsyncID[1]);
    sysevent_set_options(sd->sefd, sd->setok, "erouter_mode-updated", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sd->sefd, sd->setok, "erouter_mode-updated", &l_sAsyncID[2]);
    sysevent_set_options(sd->sefd, sd->setok, "dhcp_client-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sd->sefd, sd->setok, "dhcp_client-restart", &l_sAsyncID[3]);
    sysevent_set_options(sd->sefd, sd->setok, "dhcp_client-release", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sd->sefd, sd->setok, "dhcp_client-release", &l_sAsyncID[4]);
    sysevent_set_options(sd->sefd, sd->setok, "dhcp_client-renew", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sd->sefd, sd->setok, "dhcp_client-renew", &l_sAsyncID[5]);

    for (;;)
    {
        char name[BUFF_LEN_128], val[BUFF_LEN_128];
        memset(name,0,sizeof(name));
        memset(val,0,sizeof(val));
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sd->sefd, sd->setok, name, &namelen,
                                       val, &vallen, &getnotification_id);

        if (err)
        {
            CcspTraceError(("SysEvent get notification ERROR : %d \n", err));
        }
        else
        {
            CcspTraceInfo(("SysEvent %s Received \n", name));
            if (!strncmp(name,"dhcp_client-start",17))
            {
                dhcpv4_client_service_start(sd);
            }
            else if (!strncmp(name,"dhcp_client-stop",16))
            {
                dhcpv4_client_service_stop(sd);
            }
            else if ((!strncmp(name,"erouter_mode-updated",20)) ||
                     (!strncmp(name,"dhcp_client-restart",19)))
            {
                dhcpv4_client_service_restart(sd);
            }
            else if (!strncmp(name,"dhcp_client-release",19))
            {
                dhcpv4_client_service_release(sd);
            }
            else if (!strncmp(name,"dhcp_client-renew",17))
            {
                dhcpv4_client_service_renew(sd);
            }
        }

    }
    CcspTraceInfo(("Exiting thread \n"));
    return NULL;
}

/**********************************************************************
    function:
        dhcpv4_client_start
    description:
        This function is to start the dhcpv4 client process.
    argument:
        serv_dhcp *sd
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_start
(
    serv_dhcp *sd
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    int err = 0;
    char l_cErouter_Mode[BUFF_LEN_16] = {0}, l_cWan_if_name[BUFF_LEN_16] = {0}, cEthWanMode[BUFF_LEN_8] = {0};

    syscfg_get(NULL, "last_erouter_mode", l_cErouter_Mode, sizeof(l_cErouter_Mode));
    syscfg_get(NULL, "wan_physical_ifname", l_cWan_if_name, sizeof(l_cWan_if_name));
    syscfg_get(NULL, "eth_wan_enabled", cEthWanMode, sizeof(cEthWanMode));

    //if the syscfg is not giving any value hardcode it to erouter0
    get_dhcpc_pidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if (0 == l_cWan_if_name[0])
    {
        strncpy(l_cWan_if_name, "erouter0", BUFF_LEN_8);
        l_cWan_if_name[BUFF_LEN_8] = '\0';
    }
    if (sd->rtmod == RTMOD_IPV4 || sd->rtmod == RTMOD_DS)
    {
        CcspTraceInfo(("RTMOD = %d \n", sd->rtmod));
        /*TCHXB6 is configured to use udhcpc */
        #if defined(_PLATFORM_IPQ_)
            err = v_secure_system("/sbin/udhcpc -t 5 -n -i %s -p %s -s /etc/udhcpc.script",
                                   sd->ifname, DHCPC_PID_FILE);

            /* DHCP client didn't able to get Ipv4 configurations */
            if ( -1 == access(DHCPC_PID_FILE, F_OK) )
            {
                CcspTraceInfo(("WAN service not able to get IPv4 configuration in 5 lease try"));
            }
        #elif defined (_COSA_INTEL_XB3_ARM_) || defined (INTEL_PUMA7)
        {
            char udhcpflag[BUFF_LEN_16]="";
            syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));

            if( 0 == strcmp(udhcpflag,"true"))
            {
                CcspTraceInfo(("UDHCPC Enable = TRUE \n"));
                char options[VENDOR_OPTIONS_LENGTH];
                if ((err = dhcp_parse_vendor_info(options, VENDOR_OPTIONS_LENGTH,cEthWanMode)) == 0)
                {
                    err = vsystem("/sbin/udhcpc -i %s -p %s -V eRouter1.0 -O ntpsrv -O timezone "
                                  "-O 125 -O 2 -x %s -s /usr/bin/service_udhcpc",
                                  sd->ifname, DHCPC_PID_FILE, options);
                }
            }
            else
            {
                //#if defined (INTEL_PUMA7)
                //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
                err = v_secure_system("ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s "
                                      "-H DocsisGateway -p %s -B -b 4",
                                      sd->ifname, DHCPC_PID_FILE);
                //#else
                    /*err = vsystem("ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s "
                                  "-H DocsisGateway -p %s -B -b 1",
                                  sd->ifname, DHCPC_PID_FILE);*/
                //#endif
            }
        }
        #else
            char options[VENDOR_OPTIONS_LENGTH];
            if ((err = dhcp_parse_vendor_info(options, VENDOR_OPTIONS_LENGTH,cEthWanMode)) == 0)
            {
                #if defined (_XB6_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_) // TCXB6 and TCXB7 only
                    // tcxb6-6655, add "-b" option, so that, udhcpc forks to
                    // background if lease cannot be immediately negotiated.

                    // In ethwan mode send dhcp options part of dhcp-client to get the
                    // eMTA dhcp options

                    #if defined (EROUTER_DHCP_OPTION_MTA)
                        if (strcmp(cEthWanMode, "true") == 0 )
                        {
                            err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O "
                                           "timezone -O 122 -O 125 -O 2 -x %s "
                                           "-x 125:0000118b0701027B7C7c0107 -s "
                                           "/etc/udhcpc.script",
                                           sd->ifname, DHCPC_PID_FILE, options);
                        }
                        else
                        {
                            err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O "
                                           "timezone -O 125 -O 2 -x %s -s "
                                           "/etc/udhcpc.script",
                                           sd->ifname, DHCPC_PID_FILE, options);
                        }
                    #else
                        {
                            err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O "
                                           "timezone -O 125 -O 2 -x %s -s "
                                           "/etc/udhcpc.script",
                                           sd->ifname, DHCPC_PID_FILE, options);
                        }
                    #endif
                #else
                    #if !defined (_HUB4_PRODUCT_REQ_)
                        err = vsystem("/sbin/udhcpc -i %s -p %s -V eRouter1.0 -O ntpsrv -O "
                                      "timezone -O 125 -O 2 -x %s -s /etc/udhcpc.script",
                                       sd->ifname, DHCPC_PID_FILE, options);
                    #endif
                #endif
            }
        #endif

/*
        err = vsystem("strace -o /tmp/stracelog -f ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s "
              "-H DocsisGateway -p %s -B -b 1",
              ifname, DHCPC_PID_FILE);
*/
        if (err != 0)
        {
            CcspTraceError(("Failed to start udhcp"));
        }
    }
    return err == 0 ? 0 : -1;
}

/**********************************************************************
    function:
        dhcpv4_client_stop
    description:
        This function is to stop the dhcpv4 client process.
    argument:
        const char *ifname,     interface name
    return:
        0  if success
        -1 if error
**********************************************************************/
int dhcpv4_client_stop
(
    const char *ifname
)
{
    CcspTraceInfo(("%s: BEGIN \n", __FUNCTION__));
    FILE *fp;
    char pid_str[BUFF_LEN_16];
    int pid = -1;

    get_dhcpc_pidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if ((fp = fopen(DHCPC_PID_FILE, "rb")) != NULL)
    {
        if (fgets(pid_str, sizeof(pid_str), fp) != NULL && atoi(pid_str) > 0)
        {
            pid = atoi(pid_str);
        }
        fclose(fp);
    }

    if (pid <= 0)
    {
        #if defined(_PLATFORM_IPQ_)
            pid = pid_of("udhcpc", ifname);
        #elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
        {
            char udhcpflag[BUFF_LEN_16]="";
            syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
            if( 0 == strcmp(udhcpflag,"true"))
            {
                pid = pid_of("udhcpc", ifname);
            }
            else
            {
                pid = pid_of("ti_udhcpc", ifname);
            }
        }
        #else
            pid = pid_of("udhcpc", ifname);
        #endif
    }
    if (pid > 0)
    {
        kill(pid, SIGUSR2); // triger DHCP release
        sleep(1);
        kill(pid, SIGTERM); // terminate DHCP client

        /*
        sleep(1);
        if (pid_of("ti_udhcpc", ifname) == pid)
        {
            CcspTraceInfo(("%s: ti_udhcpc is still exist ! kill -9 it\n", __FUNCTION__));
            kill(pid, SIGKILL);
        }
        */
        #if defined (_PROPOSED_BUG_FIX_)
            syslog(LOG_INFO, "%u-%s", EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED,
                                      EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED_STR);
        #endif
    }
/*
    for (unsigned int i = 0; i < MAX_EVENTS; i++)
    {
        sysevent_rmnotification(sd->sefd, sd->setok, l_sAsyncID[i]);
    }

    CcspTraceInfo(("Removing all the sysevent notifications Before killing dhcpv4_client_sysevent_handler \n"));

    pthread_cancel(sysevent_tid);
    CcspTraceInfo(("Killed dhcpv4_client_sysevent_handler monitor thread \n"));
*/
    unlink(DHCPC_PID_FILE);
    unlink("/tmp/udhcp.log");
    return 0;
}
