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

#include "ccsp_custom.h"
#include "ccsp_psm_helper.h"
#include "ccsp_base_api.h"
#include "ccsp_memory.h"
#include "ccsp_trace.h"

extern void* g_vBus_handle;

#if defined(_COSA_INTEL_XB3_ARM_) || defined(INTEL_PUMA7)
#define DHCPV6_BINARY   "ti_dhcp6c"
#define DHCPV6_PID_FILE "/var/run/erouter_dhcp6c.pid"
#else
#define DHCPV6_BINARY   "dibbler-client"
#define DHCPV6_PID_FILE "/tmp/dibbler/client.pid"
#endif

void init_dhcpv6_client ();
void deinit_dhcpv6_client ();
void dhcpv6_client_service_start();
void dhcpv6_client_service_stop();
void dhcpv6_client_service_update();
void dhcpv6_client_service_enable();
void dhcpv6_client_service_disable();
