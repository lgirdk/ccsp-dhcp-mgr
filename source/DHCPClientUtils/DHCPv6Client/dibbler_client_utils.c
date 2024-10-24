/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "dibbler_client_utils.h"

#ifdef FEATURE_MAPT
#include <syscfg/syscfg.h>
#endif

#ifdef DHCPV6_CLIENT_DIBBLER

#define LOCALHOST         "127.0.0.1"
#define MAPT_SYSEVENT_NAME "mapt_evt_handler"

#ifdef FEATURE_MAPT
#define SYSCFG_MAPT_FEATURE_ENABLE   "MAPT_Enable"
#endif

extern token_t dhcp_sysevent_token;
extern int dhcp_sysevent_fd;
static void generate_client_duid_conf(char path[],char *ifname);

/*
 * return_dibbler_pid ()
 * @description: This function will return the pid of the dibbler-client process
 * @return     : returns a pid of runnning dibbler-client
 *
 */
pid_t return_dibbler_pid ()
{
    pid_t pid = 0;
    FILE * pidfile_fd = NULL;

    pidfile_fd = fopen(DIBBLER_CLIENT_PIDFILE, "r");

    if (pidfile_fd == NULL)
    {
        DBG_PRINT("%s %d: Unable to open pidfile: %s due to errorno: %s\n", __FUNCTION__, __LINE__, DIBBLER_CLIENT_PIDFILE, strerror(errno));
        return pid;
    }

    fscanf(pidfile_fd, "%d", &pid);

    DBG_PRINT("%s %d: pid of dibbler is %d.\n", __FUNCTION__, __LINE__, pid);
    return pid;

}

static int copy_file (char * src, char * dst)
{
    if ((src == NULL) || (dst == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    FILE * fin = NULL;
    FILE * fout = NULL;

    fout = fopen(dst, "wb");
    if (fout == NULL)
    {
        DBG_PRINT("%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, dst);
        return FAILURE;
    }

    fin = fopen(src, "r");

    if (fin == NULL)
    {
        DBG_PRINT("%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, src);
        fclose (fout);
        return FAILURE;
    }

    ssize_t nread;
    size_t len = 0;
    char *line = NULL;

    while ((nread = getline(&line, &len, fin)) != -1)
    {
        fwrite(line, nread, 1, fout);
    }

    if (line)
    {
        free(line);
    }
    fclose(fin);
    fclose(fout);

    DBG_PRINT ("%s %d: successfully copied content from %s to %s\n", __FUNCTION__, __LINE__, src, dst);
    return SUCCESS;

}


static void convert_option16_to_hex(char **optionVal)
{
    if(*optionVal == NULL)
    {
        return;
    }

    char enterprise_number_string[5] = {'\0'};
    int enterprise_number;
    int enterprise_number_len = 4;
    char temp[10] ={0};

    // we receive option value in  [enterprise_number(4 bytes) + vendor-class-data field] format. Parse enterprise_number and covnert to int.
    strncpy(enterprise_number_string, *optionVal, enterprise_number_len);
    enterprise_number = atoi(enterprise_number_string);

    //lenth to store option in hex (0x...) format
    // 2 (length for "0x") + length to store option value in %02X (2 * (len of null + length to store data_field_length  + len of *optionVal + len of null)) + 1 (null)
    int optlen = 2 + 2 * (1 + 1 + strlen(*optionVal) + 1) + 1;
    char * option16 = malloc (optlen);

    memset (option16, 0 , optlen);

    //convert and store the values in hex format
    snprintf(option16, 11, "0x%08X", enterprise_number);

    //append null
    snprintf(temp, 3, "%02X", '\0');
    strncat(option16,temp,3);

    int data_field_length = (int)strlen(*optionVal+enterprise_number_len);

    //append length of data_field_length+null
    sprintf(temp, "%02X", (data_field_length+1));
    strncat(option16,temp,3);

    for(int i=0; i<=data_field_length; i++)
    {
        snprintf(temp, 3, "%02X", (*optionVal)[enterprise_number_len+i]);
        strncat(option16,temp,3);
    }
    free(*optionVal);
    *optionVal = option16;

    return;
}

/*
 * dibbler_client_prepare_config ()
 * @description: This function will construct conf file to configure dibbler-client
 * @params     : req_opt_list - input list of DHCPv6 GET options
                 send_opt_list - input list of DHCPv6 send options

 * @return     : SUCCESS if config file written successfully, else returns FAILURE
 *
 */
static int dibbler_client_prepare_config (dibbler_client_info * client_info)
{
    if (client_info == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    dhcp_params * param = client_info->if_param;
    dhcp_opt_list * req_opt_list = client_info->req_opt_list;
    dhcp_opt_list * send_opt_list = client_info->send_opt_list;

    if (param == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    FILE * fin;
    FILE * fout;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    bool optionTempFound = 0;
    bool option20Found = 0;


    DBG_PRINT("%s %d: \n", __FUNCTION__, __LINE__);
    char args [BUFLEN_128] = {0};

#ifdef FEATURE_MAPT
    char mapt_feature_enable[BUFLEN_16] = {0};
#endif

    fout = fopen(DIBBLER_TEMPLATE_CONFIG_FILE, "wb");
    fin = fopen(DIBBLER_TMP_CONFIG_FILE, "r");
    if (fin == NULL || fout == NULL)
    {
        DBG_PRINT("%s %d: failed to open files %s %s\n", __FUNCTION__, __LINE__, DIBBLER_TEMPLATE_CONFIG_FILE, DIBBLER_TMP_CONFIG_FILE);
        return FAILURE;
    }

    while ((read = getline(&line, &len, fin)) != -1)
    {
        if (strstr(line, "iface "))
        {
            memset (&args, 0, sizeof(args));
            snprintf (args, sizeof(args), "\niface %s {\n", param->ifname);
            fputs(args, fout);
            continue;
        }
        if (param->ifType == WAN_LOCAL_IFACE)
        {
            // configuration options for local interface
            if (strstr(line, "option"))
            {
                if (!optionTempFound)
                {
                    optionTempFound = 1;
                    dhcp_opt_list * opt_list = req_opt_list;
                    while (opt_list)
                    {
                        memset (&args, 0, BUFLEN_128);

                        if (opt_list->dhcp_opt == DHCPV6_OPT_23)
                        {
                            snprintf (args, BUFLEN_128, "\n %s \n", "    option dns-server");
                            fputs(args, fout);
                        }
                        else if (opt_list->dhcp_opt == DHCPV6_OPT_24)
                        {
                            snprintf (args, BUFLEN_128, "\n %s \n", "   option domain");
                            fputs(args, fout);
                        }
                        else if (opt_list->dhcp_opt == DHCPV6_OPT_95)
                        {

#ifdef FEATURE_MAPT
                            if (syscfg_get(NULL, SYSCFG_MAPT_FEATURE_ENABLE, mapt_feature_enable, sizeof(mapt_feature_enable)) == 0)
                            {
                                if (strncmp(mapt_feature_enable, "true", 4) == 0)
                                {
#endif
                                    snprintf (args, BUFLEN_128, "\n        option 00%d hex \n", opt_list->dhcp_opt);
                                    fputs(args, fout);
#ifdef FEATURE_MAPT
                                }
                            }
#endif
                        }
                        else
                        {
                            snprintf (args, BUFLEN_128, "\n        option 00%d hex \n", opt_list->dhcp_opt);
                            fputs(args, fout);
                        }
                        opt_list = opt_list->next;
                    }

                    //send option list
                    opt_list = send_opt_list;
                    while (opt_list)
                    {
                        memset (&args, 0, BUFLEN_128);

                        if (opt_list->dhcp_opt == DHCPV6_OPT_16)
                        {
                            convert_option16_to_hex(&opt_list->dhcp_opt_val);
                            snprintf (args, BUFLEN_128, "\n\toption 00%d hex %s\n", opt_list->dhcp_opt, opt_list->dhcp_opt_val);
                            fputs(args, fout);
                        }
                        else if (opt_list->dhcp_opt == DHCPV6_OPT_15)
                        {
                            char str[32]={0};
                            char option15[100]={0};
                            char temp[16]={0};

                            strncpy(str,opt_list->dhcp_opt_val,strlen(opt_list->dhcp_opt_val)+1);

                            snprintf(temp, 8, "0x%04X",(int)strlen(str)+1);
                            strncat(option15,temp,8);

                            for(int i=0; i<(int)strlen(str)+1; i++)
                            {
                                snprintf(temp, 3, "%02X",str[i]);
                                strncat(option15,temp,3);
                            }

                            snprintf (args, BUFLEN_128, "\n\toption 00%d hex %s\n", opt_list->dhcp_opt,option15 );
                            fputs(args, fout);

                        }
                        else if (opt_list->dhcp_opt == DHCPV6_OPT_20)
                        {
                            option20Found = 1;
                        }
                        opt_list = opt_list->next;
                    }

                }
            }
            else
            {
                fputs(line, fout);
            }
        }
    }
    if(option20Found)
    {
        snprintf (args, BUFLEN_128, "\n%s\n", "reconfigure-accept 1");
        fputs(args, fout);
    }

    fclose(fin);
    fclose(fout);
    if (line)
    {
        free(line);
    }

    // write the config path into the buffer
    snprintf(client_info->config_path, sizeof(client_info->config_path), "%s%s", DIBBLER_DFT_PATH, param->ifname);

    struct stat st = {0};

    if (stat(client_info->config_path, &st) == -1)
    {
        // directory does not exists, so create it
        mkdir(client_info->config_path, 0644);
        DBG_PRINT ("%s %d: created directory %s\n", __FUNCTION__, __LINE__, client_info->config_path);
    }

    // copy the file to new location
    char file_path[BUFLEN_128] = {0};
    int ret = snprintf(file_path, sizeof(file_path), "%s/%s", client_info->config_path, DIBBLER_CLIENT_CONFIG_FILE);
    if (ret <= 0)
    {
        DBG_PRINT("%s %d: unable to contruct filepath\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (copy_file (DIBBLER_TEMPLATE_CONFIG_FILE, file_path) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to copy %s to %s due to %s\n", __FUNCTION__, __LINE__, DIBBLER_TEMPLATE_CONFIG_FILE, file_path, strerror(errno));
        return FAILURE;
    }

    DBG_PRINT("%s %d: sucessfully Updated %s/%s file with Request Options \n", __FUNCTION__, __LINE__, file_path, DIBBLER_TEMPLATE_CONFIG_FILE);
    return SUCCESS;

}

#define DUID_CLIENT "%s/client-duid"
#if defined (DUID_UUID_ENABLE)

#define DUID_TYPE "0004"  /* duid-type duid-uuid 4 */

#else

#define DUID_TYPE "00:03:"  /* duid-type duid-ll 3 */
#define HW_TYPE "00:01:"    /* hw type is always 1 */

#endif

static void generate_client_duid_conf(char path[],char *ifname)
{
    char duid[256]            = {0};
    char file_path[64]        = {0};
    char interface_mac[64]    = {0};
    char client_duid_path[64] = {0};
#if defined (DUID_UUID_ENABLE)
    char uuid[128]            = {0};
    FILE *fp_uuid_proc        = NULL;
#endif
    FILE *fp_duid             = NULL;
    FILE *fp_mac_addr_table   = NULL;

    sprintf(client_duid_path,DUID_CLIENT,path);
    fp_duid = fopen(client_duid_path, "r");
    syscfg_init();
    if( fp_duid == NULL )
    {
/* Since we pass the interface name as a argument, We don't need to get wan interface and process them only*/
#if defined (DUID_UUID_ENABLE)
        /* Removed syscfg support becasue of multiple dibbler instance environment*/
        snprintf(file_path, sizeof(file_path), "cat /proc/sys/kernel/random/uuid | tr -d - | tr -d '\t\n\r'");
        fp_uuid_proc = popen(file_path, "r");
        if(fp_uuid_proc == NULL){
            DBG_PRINT("Failed to open proc entry");
        }
        else{
            fgets(uuid, sizeof(uuid), fp_uuid_proc);
            pclose(fp_uuid_proc);
        }
#endif
        sprintf(file_path, "/sys/class/net/%s/address", ifname);
        fp_mac_addr_table = fopen(file_path, "r");
        if(fp_mac_addr_table == NULL)
        {
             DBG_PRINT("Failed to open mac address table");
        }
        else
        {
            fread(interface_mac, sizeof(interface_mac),1, fp_mac_addr_table);
            fclose(fp_mac_addr_table);
        }

        fp_duid = fopen(client_duid_path, "w");

        if(fp_duid)
        {
            sprintf(duid, DUID_TYPE);
#if defined (DUID_UUID_ENABLE)
            sprintf(duid+4, uuid);
#else
            sprintf(duid+6, HW_TYPE);
            sprintf(duid+12, interface_mac);
#endif
            fprintf(fp_duid, "%s", duid);
            fclose(fp_duid);
        }
    }
     else
    {
        fclose(fp_duid);
        DBG_PRINT("dibbler client-duid file exist");
    }

    return;
}

/*
 * start_dibbler ()
 * @description: This function will build udhcpc request/send options and start dibbler client program.
 * @params     : params - input parameter to pass interface specific arguments
 *               v4_req_opt_list - list of DHCP REQUEST options
 *               v4_send_opt_list - list of DHCP SEND options
 * @return     : returns the pid of the udhcpc client program else return error code on failure
 *
 */
pid_t start_dibbler (dhcp_params * params, dhcp_opt_list * req_opt_list, dhcp_opt_list * send_opt_list)
{

    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    dibbler_client_info client_info;

    memset (&client_info, 0, sizeof(dibbler_client_info));
    client_info.if_param = params;
    client_info.req_opt_list = req_opt_list;
    client_info.send_opt_list = send_opt_list;

    if ((dibbler_client_prepare_config(&client_info) != SUCCESS) && (client_info.config_path != NULL))
    {
        DBG_PRINT("%s %d: Unable to get DHCPv6 REQ OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    generate_client_duid_conf(client_info.config_path,params->ifname);

    DBG_PRINT("%s %d: Starting dibbler with config %s\n", __FUNCTION__, __LINE__, client_info.config_path);

    char cmd_args[BUFLEN_256] = {0};
    snprintf(cmd_args, sizeof(cmd_args), "%s -w %s", DIBBLER_CLIENT_RUN_CMD, client_info.config_path);

    pid_t ret = start_exe(DIBBLER_CLIENT_PATH, cmd_args);
    if (ret <= 0)
    {
        DBG_PRINT("%s %d: unable to start dibbler-client %d.\n", __FUNCTION__, __LINE__, ret);
        return FAILURE;
    }

    //dibbler-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(ret, DIBBLER_CLIENT_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, ret);
    }

    DBG_PRINT("%s %d: Started dibbler-client. returning pid..\n", __FUNCTION__, __LINE__);
    return get_process_pid (DIBBLER_CLIENT, NULL, true);

}

/*
 * stop_dibbler ()
 * @description: This function will stop dibbler instance that is running for interface name passed in params.ifname
 * @params     : params - input parameter to pass interface specific arguments
 * @return     : returns the SUCCESS or FAILURE
 *
 */
int stop_dibbler (dhcp_params * params)
{
    if ((params == NULL) || (params->ifname == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    pid_t pid = 0;
    char cmdarg[BUFLEN_32] = {0};

    snprintf(cmdarg, sizeof(cmdarg), "%s%s", DIBBLER_DFT_PATH, params->ifname);
    pid = get_process_pid(DIBBLER_CLIENT, cmdarg, false);

    if (pid <= 0)
    {
        DBG_PRINT("%s %d: unable to get pid of %s\n", __FUNCTION__, __LINE__, DIBBLER_CLIENT);
        return FAILURE;
    }

    if (signal_process(pid, SIGTERM) != RETURN_OK)
    {
        DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
        return FAILURE;
    }

    return SUCCESS;

}


#endif  // DHCPV6_CLIENT_DIBBLER
