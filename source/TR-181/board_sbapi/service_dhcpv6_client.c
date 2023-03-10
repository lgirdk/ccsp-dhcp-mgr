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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <errno.h>
#include <stdarg.h>
#include <service_dhcpv6_client.h>
#include <sys/sysinfo.h>
#include <util.h>
#include <safec_lib_common.h>
#include <secure_wrapper.h>
#include <libnet.h>

#define DHCPV6_CONF_FILE    "/etc/dhcp6c.conf"
#define DHCPV6_REGISTER_FILE    "/tmp/dhcpv6_registered_events"
#define DHCP6C_PROGRESS_FILE    "/tmp/dhcpv6c_inprogress"
#define DIBBLER_DEBUG_DIR   "/var/log/dibbler"
#define DIBBLER_INFO_DIR    "/tmp/.dibbler-info"

#define BUFF_LEN_8    8
#define BUFF_LEN_16    16
#define BUFF_LEN_32    32
#define BUFF_LEN_64    64
#define BUFF_LEN_128    128
#define BUFF_LEN_256    256

int g_iSyseventfd;
token_t g_tSysevent_token;

#if defined(_COSA_INTEL_XB3_ARM_) || defined(INTEL_PUMA7)
#define DHCPV6_BINARY   "ti_dhcp6c"
#define DHCPV6_PID_FILE "/var/run/erouter_dhcp6c.pid"
#else
#define DHCPV6_BINARY   "dibbler-client"
#define DHCPV6_PID_FILE "/tmp/dibbler/client.pid"
#endif

static inline void remove_file(char *tb_removed_file)
{
    int l_iRemove_Res;
    char file_name[BUFF_LEN_64] = {0};
    errno_t safec_rc = -1;
    safec_rc = strcpy_s(file_name, BUFF_LEN_64, tb_removed_file);
    ERR_CHK(safec_rc);

    if (access(file_name, F_OK) == 0)
    {
        l_iRemove_Res = remove(tb_removed_file);
        if (0 != l_iRemove_Res)
        {
            CcspTraceInfo(("SERVICE_DHCP6C : remove of %s file is not successful error is:%d\n", tb_removed_file, errno));
        }
    }
    else
    {
        CcspTraceInfo(("SERVICE_DHCP6C : Requested File %s is not available\n", tb_removed_file));
    }

}

void copy_command_output(char *cmd, char *out, int len)
{
    FILE *l_fFp = NULL;
    errno_t safec_rc = -1;
    int buff_len;
    char l_cBuf[BUFF_LEN_256] = {0};
    l_fFp = popen(cmd, "r");
    if (l_fFp)
    {
        fgets(l_cBuf, sizeof(l_cBuf), l_fFp);
        /*we need to remove the \n char in buf*/
        if(l_cBuf[strlen(l_cBuf)-1] == '\n')
        {
            l_cBuf[strlen(l_cBuf)-1] = '\0';
        }
        buff_len = strlen(l_cBuf);
        if (buff_len > len)
        {
            CcspTraceInfo(("SERVICE_DHCP6C : Warning Output will be truncated\n"));
        }
        safec_rc = strcpy_s(out, len-1, l_cBuf);
        ERR_CHK(safec_rc);

        pclose(l_fFp);
    }
}

void dhcpv6_client_service_start ()
{
    CcspTraceInfo(("SERVICE_DHCP6C : SERVICE START\n"));

    char l_cLastErouterMode[BUFF_LEN_8] = {0}, l_cWanLinkStatus[BUFF_LEN_16] = {0}, l_cWanIfname[BUFF_LEN_16] = {0},
         l_cBridgeMode[BUFF_LEN_16] = {0}, l_cWanState[BUFF_LEN_16] = {0}, l_cDibblerEnable[BUFF_LEN_16] = {0},
         l_cPhylinkWanState[BUFF_LEN_16] = {0};

    int ret = 0;

    if(0 != mkdir(DIBBLER_DEBUG_DIR, 0777))
    {
        CcspTraceInfo(("SERVICE_DHCP6C : Failed to create %s Directory\n",DIBBLER_DEBUG_DIR));
    }

    syscfg_get(NULL, "last_erouter_mode", l_cLastErouterMode, sizeof(l_cLastErouterMode));
    syscfg_get(NULL, "dibbler_client_enable", l_cDibblerEnable, sizeof(l_cDibblerEnable));
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "current_ipv4_link_state", l_cPhylinkWanState, sizeof(l_cPhylinkWanState));
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "wan_ifname", l_cWanIfname, sizeof(l_cWanIfname));
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "phylink_wan_state", l_cWanLinkStatus, sizeof(l_cWanLinkStatus));
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "bridge_mode", l_cBridgeMode, sizeof(l_cBridgeMode));
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "wan-status", l_cWanState, sizeof(l_cWanState));

    if ((strncmp(l_cLastErouterMode, "2", 1)) && (strncmp(l_cLastErouterMode, "3", 1)))
    {
        CcspTraceInfo(("SERVICE_DHCP6C : Non IPv6 Mode, service_stop\n"));
        dhcpv6_client_service_stop();
    }
    else if ((!strncmp(l_cWanLinkStatus, "down", 4)))
    {
        CcspTraceInfo(("SERVICE_DHCP6C : WAN LINK is Down, service_stop\n"));
        dhcpv6_client_service_stop();
    }
    else if (l_cWanIfname == NULL)
    {
        CcspTraceInfo(("SERVICE_DHCP6C : WAN Interface not configured, service_stop\n"));
        dhcpv6_client_service_stop();
    }
    else if ((!strncmp(l_cBridgeMode, "1", 1)))
    {
        CcspTraceInfo(("SERVICE_DHCP6C : BridgeMode, service_stop\n"));
        dhcpv6_client_service_stop();
    }
    else if ((!strncmp(l_cWanState, "stopped", 7)))
    {
        CcspTraceInfo(("SERVICE_DHCP6C : WAN state stopped, service_stop\n"));
        dhcpv6_client_service_stop();
    }
    else if (access(DHCPV6_PID_FILE, F_OK) != 0)
    {
        if (access(DHCP6C_PROGRESS_FILE, F_OK) != 0)
        {
            FILE *fp;
            fp  = fopen (DHCP6C_PROGRESS_FILE, "w");
            fclose(fp);
            CcspTraceInfo(("SERVICE_DHCP6C : Starting DHCPv6 Client from service_dhcpv6_client binary\n"));
#if defined(_COSA_INTEL_XB3_ARM_) || defined(INTEL_PUMA7)
            if (strncmp(l_cDibblerEnable, "true", 4))
            {
                CcspTraceInfo(("SERVICE_DHCP6C : Starting ti_dhcp6c\n"));
                ret = v_secure_system("ti_dhcp6c -i %s -p %s -plugin /fss/gw/lib/libgw_dhcp6plg.so",l_cWanIfname,DHCPV6_PID_FILE);
                if(ret !=0)
                {
                    CcspTraceError(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
                }
            }
#else
            if(0 != mkdir(DIBBLER_INFO_DIR, 0777))
            {
                CcspTraceInfo(("SERVICE_DHCP6C : Failed to create %s Directory\n",DIBBLER_INFO_DIR));
            }
            //Dibbler-init is called to set the pre-configuration for dibbler
            CcspTraceInfo(("SERVICE_DHCP6C :%s dibbler-init.sh Called \n", __func__));
            ret = v_secure_system("/lib/rdk/dibbler-init.sh");
            if(ret !=0)
            {
                CcspTraceError(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }
            CcspTraceInfo(("SERVICE_DHCP6C :%s Dibbler Client Started \n", __func__));
            ret = v_secure_system("%s start",DHCPV6_BINARY);
            if(ret !=0)
            {
                CcspTraceError(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }
            CcspTraceInfo(("SERVICE_DHCP6C :%s Dibbler Client Started Binary called is %s\n", __func__, DHCPV6_BINARY));
#endif
            remove_file(DHCP6C_PROGRESS_FILE);
        }
        else
        {
           CcspTraceInfo(("SERVICE_DHCP6C : DHCPv6 Client process start in progress, not starting one more\n"));
        }
    }
}

void dhcpv6_client_service_stop ()
{
    CcspTraceInfo(("SERVICE_DHCP6C : SERVICE STOP\n"));
    char l_cDibblerEnable[BUFF_LEN_8] = {0}, l_cDSLiteEnable[BUFF_LEN_8] = {0};
    int ret = 0;

    syscfg_get(NULL, "dibbler_client_enable", l_cDibblerEnable, sizeof(l_cDibblerEnable));
    syscfg_get(NULL, "dslite_enable", l_cDSLiteEnable, sizeof(l_cDSLiteEnable));

#if defined(_COSA_INTEL_XB3_ARM_) || defined(INTEL_PUMA7)
    if (strncmp(l_cDibblerEnable, "true", 4))
    {
        if (access(DHCPV6_PID_FILE, F_OK) == 0)
        {
            int pid = -1;

            if (!strncmp(l_cDSLiteEnable, "1", 1))
            {
                // We need to make sure the erouter0 interface is UP when the DHCPv6 client process plan to send
                // the RELEASE message. Otherwise it will wait to send the message and get messed when another
                // DHCPv6 client process plan to start in service_start().
                char l_cCommand[BUFF_LEN_128] = {0}, l_cErouter0Status[BUFF_LEN_8] = {0};
                snprintf(l_cCommand, sizeof(l_cCommand),"ip -d link show erouter0 | grep state | awk '/erouter0/{print $9}'");
                copy_command_output(l_cCommand, l_cErouter0Status, sizeof(l_cErouter0Status));
                l_cErouter0Status[strlen(l_cErouter0Status)] = '\0';
                CcspTraceInfo(("SERVICE_DHCP6C : l_cErouter0Status is %s\n",l_cErouter0Status));

                if (strncmp(l_cErouter0Status, "UP", 2))
                {
#if defined(CORE_NET_LIB)
                   interface_up("erouter0");
#else
                   ret = v_secure_system("ip link set erouter0 up");
                   if(ret !=0)
                   {
                       CcspTraceError(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
                   }
#endif
                }
            }
            CcspTraceInfo(("SERVICE_DHCP6C : Sending SIGTERM to %s\n",DHCPV6_PID_FILE));

            while (0 < (pid = pid_of(DHCPV6_BINARY, NULL)))
            {
                fprintf(stderr, "SERVICE_DHCP6C : Terminating ti_dhcp6c process with pid %d\n",pid);
                kill(pid, SIGTERM);
            }
            remove_file(DHCPV6_PID_FILE);

            if (!strncmp(l_cDSLiteEnable, "1", 1))
            {
                // After stop the DHCPv6 client, need to clear the sysevent tr_erouter0_dhcpv6_client_v6addr
                // So that it can be triggered again once DHCPv6 client got the same IPv6 address with the old address
                sysevent_set(g_iSyseventfd, g_tSysevent_token, "tr_erouter0_dhcpv6_client_v6addr", "", 0);
            }
        }
    }
#endif
    ret = v_secure_system("%s stop",DHCPV6_BINARY);
    CcspTraceInfo(("SERVICE_DHCP6C : Stopping dhcpv6 client\n"));
    if(ret !=0)
    {
        CcspTraceError(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }
    remove_file(DHCPV6_PID_FILE);
}

void dhcpv6_client_service_update()
{
    CcspTraceInfo(("SERVICE_DHCP6C : Inside dhcpv6_client_service_update\n"));

    char l_cDhcpv6cEnabled[BUFF_LEN_8] = {0};

    sysevent_get(g_iSyseventfd, g_tSysevent_token, "dhcpv6c_enabled", l_cDhcpv6cEnabled, sizeof(l_cDhcpv6cEnabled));

    if (!strncmp(l_cDhcpv6cEnabled, "1", 1))
    {
        dhcpv6_client_service_start();
    }
    else
    {
        dhcpv6_client_service_stop();
    }
}

void dhcpv6_client_service_enable()
{
    CcspTraceInfo(("SERVICE_DHCP6C : SERVICE ENABLE\n"));

    char l_cDhcpv6cEnabled[BUFF_LEN_8] = {0};
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "dhcpv6c_enabled", l_cDhcpv6cEnabled, sizeof(l_cDhcpv6cEnabled));

    dhcpv6_client_service_start();
    sysevent_set(g_iSyseventfd, g_tSysevent_token, "dhcpv6c_enabled", "1", 0);
}

void dhcpv6_client_service_disable()
{
    CcspTraceInfo(("SERVICE_DHCP6C : SERVICE ENABLE\n"));

    char l_cDhcpv6cEnabled[BUFF_LEN_8] = {0};
    sysevent_get(g_iSyseventfd, g_tSysevent_token, "dhcpv6c_enabled", l_cDhcpv6cEnabled, sizeof(l_cDhcpv6cEnabled));

    if (strncmp(l_cDhcpv6cEnabled, "1", 1))
    {
        CcspTraceInfo(("SERVICE_DHCP6C : DHCPv6 Client is not enabled\n"));
        return;
    }

    sysevent_set(g_iSyseventfd, g_tSysevent_token, "dhcpv6c_enabled", "0", 0);

    CcspTraceInfo(("Removing file: %s\n", DHCP6C_PROGRESS_FILE));
    remove_file(DHCP6C_PROGRESS_FILE);

    dhcpv6_client_service_stop();
}
