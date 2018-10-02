<?php

include_once "/lib/sd_340.php";
include_once "/lib/sn_tcp_ac.php";
include_once "/lib/sn_dns.php";
include_once "/lib/sc_envs.php";

$vd_atc_uart_id = 0;
$vd_envs = "";

define("AT_MSG_OK", 0); /* basic result code */
define("AT_MSG_CONNECT", 1); /* basic result code */
define("AT_MSG_RING", 2); /* basic result code */
define("AT_MSG_NO_CARRIER", 3); /* basic result code */
define("AT_MSG_ERROR", 4); /* basic result code */
define("AT_MSG_MAX", 5);
define("AT_MSG_NO_ANSWER", 8); /* extended result code */

define("AT_STATE_CMD", 0);	// command input mode
define("AT_STATE_DIAL", 1);
define("AT_STATE_OL", 2);
define("AT_STATE_OL_CMD", 3);
define("AT_STATE_HOOK", 4);
define("AT_STATE_MAX", 5);

define("S_RINGS", 0);
define("S_RINGS_RCVD", 1);
define("S_ESC", 2);
define("S_CR", 3);
define("S_LF", 4);
define("S_BS", 5);
define("S_PING", 9);
define("S_GUARD", 12);
define("S_MAX", 16);

define("result_msg_ok", "\r\nOK\r\n");
define("result_msg_connect",  "\r\nCONNECT\r\n");
define("result_msg_ring",  "\r\nRING\r\n");
define("result_msg_no_carrier",  "\r\nNO CARRIER\r\n");
define("result_msg_error",  "\r\nERROR\r\n");
define("result_msg_no_answer",  "\r\nNO ANSWER\r\n");

define("BACKSPACE", "\x08");
define("CR", "\x0d");
define("LF", "\x0a");

define("HOST_NAME_SIZE", 32);

$vd_reg_E = 1;
$vd_reg_L = 0;
$vd_reg_M = 0;
$vd_reg_N = 1;
$vd_reg_Q = 0;
$vd_reg_V = 1;
$vd_reg_X = 0;
$vd_reg_N = 1;
$vd_reg_S = array(0,0,"",0,0,0,0,0,0,0,0,0,0,0,0,0);

$vd_at_state = AT_STATE_CMD;
$vd_cmd_len = 0;
$vd_hdr_count = 0;

$vd_cmd_buf = "";
$vd_plus_buf = "";
$vd_plus_count = 0;

//-----------------------------
$vd_local_port = "";
$vd_peer_address = "";
$vd_peer_port = 0;
$vd_host_name = "";
//-----------------------------

function vd_is_digit($ch)
{
	if($ch < "0" || $ch > "9")
		return 0;
		
	return 1;
}

function vd_at_echo($msg)
{
  global $vd_atc_uart_id, $vd_reg_E;
  
  if($vd_reg_E == 1)
    uart_write($vd_atc_uart_id, $msg);
}

function vd_at_getchar()
{
  global $vd_atc_uart_id;
  
  $rbuf = "";
  uart_readn($vd_atc_uart_id, $rbuf, 1);
  
  return $rbuf;
}

function vd_at_out($msg)
{
  global $vd_atc_uart_id;
  uart_write($vd_atc_uart_id, $msg);
}

function vd_at_result($result)
{
  global $vd_reg_Q, $vd_reg_V;

  if($vd_reg_Q == 1)
    return;

  if($vd_reg_V == 1)
  {
    switch($result)
    {
      case AT_MSG_OK:
        vd_at_out(result_msg_ok);
        break;
      case AT_MSG_CONNECT:
        vd_at_out(result_msg_connect);
        break;
      case AT_MSG_RING:
        vd_at_out(result_msg_ring);
        break;
      case AT_MSG_NO_CARRIER:
        vd_at_out(result_msg_no_carrier);
        break;
      case AT_MSG_ERROR:
        vd_at_out(result_msg_error);
        break;
      case AT_MSG_NO_ANSWER:
        vd_at_out(result_msg_no_answer);
        break;
    }
  }
  else
  {
    $msg = sprintf("\r\n%u\r\n", $result);
    vd_at_out($msg);
  }
}

function vd_at_reset()
{
	global $vd_reg_E, $vd_reg_Q, $vd_reg_V, $vd_reg_X, $vd_reg_S;
	
	$vd_reg_E = 1;
	$vd_reg_Q = 0;
	$vd_reg_V = 1;
	$vd_reg_X = 0;
	
	$vd_reg_S[S_RINGS] = 1;
	$vd_reg_S[S_ESC] = "+";
	$vd_reg_S[S_CR] = 0x0d;
	$vd_reg_S[S_LF] = 0x0a;
	$vd_reg_S[S_BS] = 0x08;
	$vd_reg_S[S_PING] = 6;
	$vd_reg_S[S_GUARD] = 50;
  
  vd_at_result(AT_MSG_NO_CARRIER);
}

//------------------------------------------------
function vd_at_read_cmd()
{
  global $vd_atc_uart_id;
  global $vd_cmd_buf, $vd_cmd_len;
	global $vd_hdr_count;
  
  for(;;)
  {
    $ch = vd_at_getchar();
    if($ch == "")
      return 0;
    
    vd_at_echo($ch);
    
    if($vd_hdr_count < 2)
    {
      if(($ch == "a") || ($ch == "A"))
      {
        $vd_hdr_count = 1;
        $vd_cmd_buf = "A";
        continue;
      }
      if(($vd_hdr_count == 1) && (($ch === "t") || ($ch === "T")))
      {
        $vd_hdr_count = 2;
        $vd_cmd_len = 2;
        $vd_cmd_buf = "AT";
      }
      else
      {
        $vd_hdr_count = 0;
        $vd_cmd_buf = "";
      }
      continue;
    }
    else
    {
      if($ch == BACKSPACE) // backspace
      {
        if($vd_cmd_len > 2)
        {
          vd_at_echo(" ");
          vd_at_echo(BACKSPACE);
          $vd_cmd_len--;
          $vd_cmd_buf = substr($vd_cmd_buf, 0, $vd_cmd_len);
        }
      }
      else if($ch == CR)
      {
        $retval = $vd_cmd_len;
        $vd_hdr_count = 0;
        return $retval;
      }
      else
			{
				$vd_cmd_len++;
				$vd_cmd_buf .= $ch;
				
				if($vd_cmd_len == MAX_STRING_LEN - 1)
				{
					$vd_hdr_count = 0;
					vd_at_result(AT_MSG_ERROR);
					continue;
				}
			}
    }
  }
}

function vd_at_parse_arg(&$at_arg, $at_cmd)
{
  $len = 0;
  $index = 0;
  if(vd_is_digit($at_cmd[$index]) == 0)
  {
    $at_arg = 0;
    return 0;
  }
  $at_arg = (int)$at_cmd;
  $len = strlen((string)$at_arg);
  
  return $len;
}

function vd_at_cmd_ip_addr(&$ip, $at_cmd)
{
  if($at_cmd[0] === '?')
  {
    vd_at_out("\r\n$ip\r\n");
    return 1;
  }
  else if($at_cmd[0] === '=')
  {
    if(strlen($at_cmd) > 1)
    {
      $res = inet_pton(substr($at_cmd, 1));
      if($res !== FALSE)
      {
        $ip = inet_ntop($res);
        $ip_len = strlen($ip);
        return $ip_len + 1;
      }
    }
  }
  
  return 0;
}

function vd_at_cmd_var(&$at_arg, $at_cmd)
{
  if($at_cmd[0] === '?')
  {
    vd_at_out("\r\n$at_arg\r\n");
    return 1;
  }
  else if($at_cmd[0] === '=')
  {
    if(strlen($at_cmd) > 1)
    {
      $at_cmd = substr($at_cmd, 1);
      $at_cmd_len = strlen($at_cmd);
      $at_arg = (int)$at_cmd;
      
      if($at_arg == 0)
      {
        if($at_cmd[0] != "0")
          return 0;
      }
      
      $len = strlen((string)$at_arg);
      return $len + 1;
    }
    return 0;
  }
  return 0;
}

function vd_at_cmd_ascii_string(&$at_arg, $at_cmd, $max_length)
{
  if($at_cmd[0] === '?')
  {
    vd_at_out("\r\n$at_arg\r\n");
    return 1;
  }
  else if($at_cmd[0] === '=')
  {
    if(strlen($at_cmd) > 3)
    {
      if($at_cmd[1] == "\"")
      {
        $pos = strpos($at_cmd, "\"", 2);
        if($pos === FALSE || ($pos - 2) > $max_length)
          return 0;
        
        $len = $pos - 2;
        $at_arg = substr($at_cmd, 2, $len);
        return $len + 3;
      }
    }
    return 0;
  }
  return 0;
}

function vd_at_cmd_extended_ip6($at_cmd)
{
  global $vd_envs, $vd_at_state;
  global $vd_peer_address, $sn_tcp_ac_pid;
  
  $index = 0;
  $cmd_len = 0;
  
  $cmd_temp = "";
  if(strlen($at_cmd) > 5)
    $cmd_temp = substr($at_cmd, 0, 5);
  else
    $cmd_temp = $at_cmd;
    
  $cmd_temp = strtoupper($cmd_temp);
    
  if(strpos($cmd_temp, "PIP6") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_IP6);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        envs_set_net_opt($vd_envs, NET_OPT_IP6, $at_arg ? 1 : 0);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PEUI") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_IP6_EUI);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        envs_set_net_opt($vd_envs, NET_OPT_IP6_EUI, $at_arg);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PGUA") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        envs_set_net_opt($vd_envs, NET_OPT_IP6_GUA, $at_arg);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PLIP6") !== FALSE)
  {
    $index += 5;
    if(strlen($at_cmd) > $index)
    {
      $env_temp = envs_find($vd_envs, ENV_CODE_IP6, 0x00);
      if(envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA) == 1)
        $at_arg = inet_ntop(substr($env_temp, 0, 16));
      else
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get ipaddr6");
        pid_close($pid);
      }
      $cmd_len = vd_at_cmd_ip_addr($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA) == 1)
          envs_update($vd_envs, ENV_CODE_IP6, 0x00, inet_pton($at_arg) . substr($env_temp, 16, 2));
        return $cmd_len + 5;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PPFX") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $env_temp = envs_find($vd_envs, ENV_CODE_IP6, 0x00);
      if(envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA) == 1)
        $at_arg = bin2int(substr($env_temp, 16, 2), 0, 2);
      else
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get prefix6");
        pid_close($pid);
      }
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA) == 1)
          envs_update($vd_envs, ENV_CODE_IP6, 0x00, substr($env_temp, 0, 16) . int2bin($at_arg, 2));
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PGIP6") !== FALSE)
  {
    $index += 5;
    if(strlen($at_cmd) > $index)
    {
      if(envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA) == 1)
        $at_arg = inet_ntop(substr(envs_find($vd_envs, ENV_CODE_IP6, 0x02), 0, 16));
      else
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get gwaddr6");
        pid_close($pid);
      }
      $cmd_len = vd_at_cmd_ip_addr($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_IP6_GUA) == 1)
          envs_update($vd_envs, ENV_CODE_IP6, 0x02, inet_pton($at_arg));
        return $cmd_len + 5;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PRIP6") !== FALSE)
  {
    $index += 5;
    if(strlen($at_cmd) > $index)
    {
      if($vd_at_state == AT_STATE_OL_CMD && tcp_state(0) == TCP_CONNECTED)
      {
        //---------------------------------------------------------
        $tcp_pid = $sn_tcp_ac_pid[0];
        $vd_peer_address = pid_ioctl($tcp_pid, "get dstaddr");
        //---------------------------------------------------------
      }
      $cmd_len = vd_at_cmd_ip_addr($vd_peer_address, substr($at_cmd, $index));
      if($cmd_len)
      {
        return $cmd_len + 5;
      }
      return 0;
    }
    return 0;
  }
  
  return 0;
}

function vd_at_cmd_extended_wlan($at_cmd)
{
  global $vd_envs;
  
  $index = 0;
  $cmd_len = 0;
  
  $cmd_temp = "";
  if(strlen($at_cmd) > 5)
    $cmd_temp = substr($at_cmd, 0, 5);
  else
    $cmd_temp = $at_cmd;
    
  $cmd_temp = strtoupper($cmd_temp);
  
  if(strpos($cmd_temp, "WLAN") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_WLAN);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        envs_set_net_opt($vd_envs, NET_OPT_WLAN, $at_arg ? 1 : 0);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WCCT") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_TSF);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        envs_set_net_opt($vd_envs, NET_OPT_TSF, $at_arg);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WCH") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_CH);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        envs_set_net_opt($vd_envs, NET_OPT_CH, $at_arg);
        return $cmd_len + 3;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WSSID") !== FALSE)
  {
    $index += 5;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = rtrim(envs_find($vd_envs, ENV_CODE_WLAN, 0x01));
      $cmd_len = vd_at_cmd_ascii_string($at_arg, substr($at_cmd, $index), 32);
      if($cmd_len)
      {
        envs_update($vd_envs, ENV_CODE_WLAN, 0x01, $at_arg);
        return $cmd_len + 5;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WPA") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_WPA);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len && $at_arg <= 3)
      {
        envs_set_net_opt($vd_envs, NET_OPT_WPA, $at_arg);
        return $cmd_len + 3;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WUID") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = rtrim(envs_find($vd_envs, ENV_CODE_NETID, 0x04));
      $cmd_len = vd_at_cmd_ascii_string($at_arg, substr($at_cmd, $index), 32);
      if($cmd_len)
      {
        envs_update($vd_envs, ENV_CODE_NETID, 0x04, $at_arg);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WUPW") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = rtrim(envs_find($vd_envs, ENV_CODE_NETID, 0x05));
      $cmd_len = vd_at_cmd_ascii_string($at_arg, substr($at_cmd, $index), 32);
      if($cmd_len)
      {
        envs_update($vd_envs, ENV_CODE_NETID, 0x05, $at_arg);
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WPP") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = rtrim(envs_find($vd_envs, ENV_CODE_WLAN, 0x08));
      $cmd_len = vd_at_cmd_ascii_string($at_arg, substr($at_cmd, $index), 63);
      if($cmd_len)
      {
        envs_update($vd_envs, ENV_CODE_WLAN, 0x08, $at_arg);
        return $cmd_len + 3;
      }
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "WPSK") !== FALSE)
  {
    $index += 4;
    $wlan_ssid = rtrim(envs_find($vd_envs, ENV_CODE_WLAN, 0x01));
    $wlan_shared_key = rtrim(envs_find($vd_envs, ENV_CODE_WLAN, 0x08));
    $wpa_psk = hash_pbkdf2("sha1", $wlan_shared_key, $wlan_ssid, 4096, 32, true);
    envs_update($vd_envs, ENV_CODE_WLAN, 0x09, $wpa_psk);
    return 4;
  }
  
  if(strpos($cmd_temp, "WLS") !== FALSE)
  {
    $index += 3;
    $pid = pid_open("/mmap/net1");
    vd_at_out("\r\n");
    vd_at_out((string)pid_ioctl($pid, "get speed"));
    vd_at_out("\r\n");
    pid_close($pid);
    return 3;
  }
  
  if(strpos($cmd_temp, "WRSSI") !== FALSE)
  {
    $index += 5;
    $pid = pid_open("/mmap/net1");
    vd_at_out("\r\n");
    vd_at_out((string)pid_ioctl($pid, "get rssi"));
    vd_at_out("\r\n");
    pid_close($pid);
    return 5;
  }
  
  return 0;
}

function vd_at_cmd_extended($at_cmd)
{
  global $vd_local_port, $vd_peer_address, $vd_peer_port, $vd_host_name;
  global $vd_at_state, $vd_reg_N, $vd_envs, $sn_tcp_ac_pid;
  
  $index = 0;
  $cmd_len = 0;
  
  if(ini_get("init_net1") === "1")
  {
    $cmd_len = vd_at_cmd_extended_wlan($at_cmd);
    if($cmd_len)
      return $cmd_len;
  }
  
  if(ini_get("init_ip6") === "1")
  {
    $cmd_len = vd_at_cmd_extended_ip6($at_cmd);
    if($cmd_len)
      return $cmd_len;
  }
  
  $cmd_temp = "";
  if(strlen($at_cmd) > 4)
    $cmd_temp = substr($at_cmd, 0, 4);
  else
    $cmd_temp = $at_cmd;
    
  $cmd_temp = strtoupper($cmd_temp);
  
  if(strpos($cmd_temp, "PLIP") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 1)
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get ipaddr");
        pid_close($pid);
      }
      else
        $at_arg = inet_ntop(substr(envs_find($vd_envs, ENV_CODE_IP4, 0x00), 0, 4));
      $cmd_len = vd_at_cmd_ip_addr($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 0)
          envs_update($vd_envs, ENV_CODE_IP4, 0x00, inet_pton($at_arg));
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PSM") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 1)
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get netmask");
        pid_close($pid);
      }
      else
        $at_arg = inet_ntop(substr(envs_find($vd_envs, ENV_CODE_IP4, 0x01), 0, 4));
      $cmd_len = vd_at_cmd_ip_addr($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 0)
          envs_update($vd_envs, ENV_CODE_IP4, 0x01, inet_pton($at_arg));
        return $cmd_len + 3;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PGIP") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 1)
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get gwaddr");
        pid_close($pid);
      }
      else
        $at_arg = inet_ntop(substr(envs_find($vd_envs, ENV_CODE_IP4, 0x02), 0, 4));
      $cmd_len = vd_at_cmd_ip_addr($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 0)
          envs_update($vd_envs, ENV_CODE_IP4, 0x02, inet_pton($at_arg));
        return $cmd_len + 4;
      }
      else
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PNIP") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 1 && envs_get_net_opt($vd_envs, NET_OPT_AUTO_NS) == 1)
      {
        $pid = pid_open("/mmap/net1");
        $at_arg = pid_ioctl($pid, "get nsaddr");
        pid_close($pid);
      }
      else
        $at_arg = inet_ntop(substr(envs_find($vd_envs, ENV_CODE_IP4, 0x03), 0, 4));
      $cmd_len = vd_at_cmd_ip_addr($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 0 || (envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 1 && envs_get_net_opt($vd_envs, NET_OPT_AUTO_NS) == 0))
          envs_update($vd_envs, ENV_CODE_IP4, 0x03, inet_pton($at_arg));
        return $cmd_len + 4;
      }
      else
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PDC") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_DHCP);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {        
        envs_set_net_opt($vd_envs, NET_OPT_DHCP, $at_arg ? 1 : 0);
        return $cmd_len + 3;
      }
      else
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PAN") !== FALSE)
  {
    if(envs_get_net_opt($vd_envs, NET_OPT_DHCP) == 0)
      return 0;
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = envs_get_net_opt($vd_envs, NET_OPT_AUTO_NS);
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {        
        envs_set_net_opt($vd_envs, NET_OPT_AUTO_NS, $at_arg ? 1 : 0);
        return $cmd_len + 3;
      }
      else
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PSE") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = $vd_reg_N;
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        $vd_reg_N = $at_arg ? 1 : 0;
        return $cmd_len + 3;
      }
      else
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PRHN") !== FALSE)
  {
    $index += 4;
    
    if(strlen($at_cmd) > $index)
    {
      if($vd_at_state != AT_STATE_CMD)
        return 0;
      
      $at_arg = $vd_host_name;
      $cmd_len = vd_at_cmd_ascii_string($at_arg, substr($at_cmd, $index), HOST_NAME_SIZE);
      
      if($cmd_len == 1)
        return $cmd_len + 4;
      
      if($cmd_len > 3)
      {
        $res = dns_lookup($at_arg, RR_A);
        $vd_host_name = $at_arg;
        $vd_peer_address = $res == $at_arg ? "" : $res;
        
        if($vd_peer_address == "")
          return 0;
        
        return $cmd_len + 4;
      }
      return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PLS") !== FALSE)
  {
    $index += 3;
    
    if(ini_get("init_net0") === "1")
    {
      $pid = pid_open("/mmap/net0");
      vd_at_out("\r\n");
      vd_at_out((string)pid_ioctl($pid, "get speed"));
      vd_at_out("\r\n");
      pid_close($pid);
      return 3;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PRIP") !== FALSE)
  {
    $index += 4;
    if(strlen($at_cmd) > $index)
    {
      if($vd_at_state == AT_STATE_OL_CMD && tcp_state(0) == TCP_CONNECTED)
      {
        //---------------------------------------------------------
        $tcp_pid = $sn_tcp_ac_pid[0];
        $vd_peer_address = pid_ioctl($tcp_pid, "get dstaddr");
        //---------------------------------------------------------
      }
      
      $cmd_len = vd_at_cmd_ip_addr($vd_peer_address, substr($at_cmd, $index));
      if($cmd_len)
      {
        return $cmd_len + 4;
      }
      else
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PLP") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      $at_arg = $vd_local_port;
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        $vd_local_port = $at_arg;
        return $cmd_len + 3;
      }
      else 
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PRP") !== FALSE)
  {
    $index += 3;
    if(strlen($at_cmd) > $index)
    {
      if($vd_at_state == AT_STATE_OL_CMD && tcp_state(0) == TCP_CONNECTED)
      {
        //---------------------------------------------------------
        $tcp_pid = $sn_tcp_ac_pid[0];
        $vd_peer_port = pid_ioctl($tcp_pid, "get dstport");
        //---------------------------------------------------------
      }
      $at_arg = $vd_peer_port;
      $cmd_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
      if($cmd_len)
      {
        $vd_peer_port = $at_arg;
        return $cmd_len + 3;
      }
      else 
        return 0;
    }
    return 0;
  }
  
  if(strpos($cmd_temp, "PRST") !== FALSE)
  {
    $index += 4;
    system("reboot sys 500");
    return $cmd_len + 4;
  }
  
  if(strpos($cmd_temp, "PWP") !== FALSE)
  {
    $index += 3;
    $wkey = envs_get_wkey(); 
    envs_write($vd_envs, $wkey);
    system("reboot sys 500");
    return $cmd_len + 3;
  }
  
  return 0;
}

function vd_at_print_ea()
{
  $pid_net = pid_open("/mmap/net1", O_NODIE);
  
  if($pid_net != -EBUSY && $pid_net != -ENOENT)
  {
    vd_at_out("\r\n");
    vd_at_out(pid_ioctl($pid_net, "get hwaddr"));
    vd_at_out("\r\n");
    pid_close($pid_net);
  }
}

function vd_at_cmd_basic($at_cmd)
{
  global $vd_reg_E;
  global $vd_reg_L;
  global $vd_reg_S;
  global $vd_reg_V;
  global $vd_reg_X;
  global $vd_reg_Q;
  global $vd_at_state;
  
	$cmd = strtoupper($at_cmd[0]);
  $cmd_len = 1;
  $index = 1;
  $at_arg = 0;
  
  switch($cmd)
  {
    case 'B':
      if(strlen($at_cmd) > 1 && vd_is_digit($at_cmd[$index]) == 1)
          return 2;
      else
        return 1;
    case 'E':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 1)
          return 0;
        $cmd_len += $s_len;
      }
      $vd_reg_E = $at_arg;
      return $cmd_len;
    case 'F':
      return 1;
    case 'I':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($s_len == 0 || $at_arg > 7)
          return 0;
        $cmd_len += $s_len;
        switch($at_arg)
        {
          case 0:
            vd_at_out("\r\n1151\r\n");
            break;
          case 1:
            vd_at_out("\r\n0000\r\n");
            break;
          case 2:
            break;
          case 3:
            vd_at_out("\r\n");
            vd_at_out(system("uname -svpi"));
            vd_at_out("\r\n");
            break;
          case 4:
            break;
          case 5:
            break;
          case 6:
            break;
          case 7:
            vd_at_print_ea();
            break;
        }
        return $cmd_len;
      }
      return 0;
    case 'L':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($s_len == 0 || $at_arg > 3)
          return 0;
        $cmd_len += $s_len;
        $vd_reg_L = $at_arg;
      }
      return $cmd_len;
    case 'M':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 3)
          return 0;
        $cmd_len += $s_len;
        $vd_reg_L = $at_arg;
      }
      return $cmd_len;
    case 'P':
      return 1;
    case 'Q':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 1)
          return 0;
        $cmd_len += $s_len;
      }
      $vd_reg_Q = $at_arg;
      return $cmd_len;
    case 'S':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($s_len)
        {
          $index += $s_len;
          if($at_arg <= S_MAX && strlen($at_cmd) > $index)
          {
            $s_id = $at_arg;
            $cmd_len += $s_len;
            if($s_id == S_ESC)
              $at_arg = bin2int($vd_reg_S[$s_id], 0, strlen($vd_reg_S[$s_id]));
            else
              $at_arg = $vd_reg_S[$s_id];
            $s_len = vd_at_cmd_var($at_arg, substr($at_cmd, $index));
            if($s_len)
            {
              if($at_arg < 256)
              {
                if($s_id == S_ESC)
                  $vd_reg_S[$s_id] = int2bin($at_arg, 1);
                else
                  $vd_reg_S[$s_id] = $at_arg;
                return $cmd_len + $s_len;
              }
              else
                return 0;
            }
          }
          else
            return 0;
        }
      }
      return 0;
    case 'T':
      return 1;
    case 'V':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 1)
          return 0;
        $cmd_len += $s_len;        
      }
      $vd_reg_V = $at_arg;
      return $cmd_len;
    case 'X':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 0)
          return 0;
        $cmd_len += $s_len;
        $vd_reg_X = $at_arg;
      }
      return $cmd_len;
    case 'Y':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 0)
          return 0;
        $cmd_len += $s_len;
      }
      return $cmd_len;
    case 'Z':
      if(strlen($at_cmd) > 1)
      {
        $s_len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 5)
          return 0;
        $cmd_len += $s_len;
      }
      if($vd_at_state == AT_STATE_OL_CMD)
        $vd_at_state = AT_STATE_HOOK;
      vd_at_reset();
      return $cmd_len;
    default:
      return 0;
  }
}

function vd_at_parse_cmd($cmd_len)
{
  global $vd_cmd_buf, $vd_at_state, $vd_peer_address, $vd_peer_port;
  
  $len = 0;
	$at_arg = 0;
  
  $at_cmd = substr($vd_cmd_buf, 2);
  $index = 0;
  while($cmd_len)
  {
    switch(strtoupper($at_cmd[$index]))
    {
      case 'A':
        $index++;
        if($vd_at_state == AT_STATE_OL_CMD)
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        tcp_server(0, 1470);
        $vd_at_state = AT_STATE_DIAL;
        return;
      case 'D':
        $index++;
        if($vd_at_state != AT_STATE_CMD)
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        tcp_client(0, $vd_peer_address, $vd_peer_port);
        $vd_at_state = AT_STATE_DIAL;
        //------------------------------
        return;
      case 'H':
        $index++;
        $cmd_len--;
        if($cmd_len > 0)
          $len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 1)
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        $index += $len;
        $cmd_len -= $len;
        if($vd_at_state == AT_STATE_OL_CMD)
        {
          if(!$at_arg)
            $vd_at_state = AT_STATE_HOOK;
        }
        break;
      case 'O':
        $index++;
        $cmd_len--;
        if($cmd_len > 0)
          $len = vd_at_parse_arg($at_arg, substr($at_cmd, $index));
        if($at_arg > 1)
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        if($vd_at_state == AT_STATE_OL_CMD && tcp_state(0) == TCP_CONNECTED)
        {
          vd_at_result(AT_MSG_CONNECT);
          $vd_at_state = AT_STATE_OL;
          return;
        }
        else
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        break;
      case '+':
        $index++;
        $cmd_len--;
        if($cmd_len > 0)
        {
          $len = vd_at_cmd_extended(substr($at_cmd, $index));
        }
        if($len)
        {
          $index += $len;
          $cmd_len -= $len;
        }
        else
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        break;
      case 'B':
      case 'E':
      case 'F':
      case 'I':
      case 'L':
      case 'M':
      case 'P':
      case 'Q':
      case 'S':
      case 'T':
      case 'V':
      case 'X':
      case 'Y':
      case 'Z':
        $len = vd_at_cmd_basic(substr($at_cmd, $index));
        if($len)
        {
          $index += $len;
          $cmd_len -= $len;
        }
        else
        {
          vd_at_result(AT_MSG_ERROR);
          return;
        }
        break;
      default:
        vd_at_result(AT_MSG_ERROR);
        return;
    }
  }
  
  vd_at_result(AT_MSG_OK);
}

function vd_do_cmd()
{
  global $vd_cmd_buf;
  
  $len = vd_at_read_cmd();
  
  if($len > 0)
  {
    error_log(sprintf("[CMD] %s", $vd_cmd_buf));
    if($len == 2)
      vd_at_result(AT_MSG_OK);
    else
      vd_at_parse_cmd($len - 2);
  }
}

function vd_at_state_cmd()
{
  vd_do_cmd();
}

$vd_esc_count = 0;
$vd_esc_temp = "";

function vd_at_state_dial()
{
  global $vd_at_state, $vd_atc_uart_id;
  global $vd_esc_count, $vd_esc_temp;
  global $vd_peer_address, $vd_peer_port;
  
  $tcp_state = tcp_state(0);
  if($tcp_state == TCP_CONNECTED)
  {
    vd_at_result(AT_MSG_CONNECT);
    
    $vd_esc_count = 0;
    $vd_esc_temp = "";
    
    $vd_at_state = AT_STATE_OL;
    return;
  }
  if($tcp_state == TCP_CLOSED)
  {
    $vd_at_state = AT_STATE_HOOK;
    return;
  }
  
  if(vd_at_getchar() != "")
  {
    $vd_at_state = AT_STATE_HOOK;
  }
}

function vd_at_state_ol()
{
  global $vd_at_state, $vd_atc_uart_id, $vd_esc_count, $vd_esc_temp;
  global $vd_reg_S, $vd_reg_N;
  
  $tcp_state = tcp_state(0);
  if($tcp_state == TCP_CONNECTED)
  {
    //----------------------------------------------------
    // UART -> TCP
    $txfree = tcp_txfree(0);
    if($txfree > 0)
    {
      $rbuf = "";
      if(($rlen = uart_read($vd_atc_uart_id, $rbuf, $txfree)) > 0)
      {
        // escape sequence
        if($vd_esc_count == 0)
        {
          if(($esc_pos = strpos($rbuf, str_repeat($vd_reg_S[S_ESC], 3))) !== FALSE)
          {
            if(!$vd_reg_N)
              $rbuf = substr($rbuf, 0, $esc_pos);
            else
              $rbuf = substr($rbuf, 0, $esc_pos + 3);
            
            tcp_write(0, $rbuf);
            
            vd_at_result(AT_MSG_OK);
            $vd_at_state = AT_STATE_OL_CMD;
          }
          else
          {
            if(substr($rbuf, $rlen - 2) == str_repeat($vd_reg_S[S_ESC], 2))
              $vd_esc_count = 2;
            else if(substr($rbuf, $rlen - 1) == $vd_reg_S[S_ESC])
              $vd_esc_count = 1;
            
            if($vd_esc_count > 0 && !$vd_reg_N)
            {
              $vd_esc_temp = str_repeat($vd_reg_S[S_ESC], $vd_esc_count);
              $rbuf = substr($rbuf, 0, $rlen - $vd_esc_count);
            }
            tcp_write(0, $rbuf);
          }
        }
        else
        {
          $esc_count = 3 - $vd_esc_count;
          $compare_length = $rlen >= $esc_count ? $esc_count : $rlen;
          
          if(substr($rbuf, 0, $compare_length) == str_repeat($vd_reg_S[S_ESC], $compare_length))
          {
            if($vd_reg_N)
              tcp_write(0, str_repeat($vd_reg_S[S_ESC], $compare_length));
            else
              $vd_esc_temp .= str_repeat($vd_reg_S[S_ESC], $compare_length);
              
            $vd_esc_count += $compare_length;
            
            if($vd_esc_count == 3)
            {
              $vd_esc_count = 0;
              $vd_esc_temp = "";
            
              vd_at_result(AT_MSG_OK);
              $vd_at_state = AT_STATE_OL_CMD;
            }
          }
          else
          {
            if($vd_esc_temp != "")
              tcp_write(0, $vd_esc_temp);
            
            $vd_esc_count = 0;
            $vd_esc_temp = "";
            
            tcp_write(0, $rbuf);
          }
        }
      }
    }
    //----------------------------------------------------    
  }
  else
  {
    $vd_at_state = AT_STATE_HOOK;
  }
}

function vd_at_state_ol_cmd()
{
  global $vd_at_state;
  if(tcp_state(0) != TCP_CONNECTED)
    $vd_at_state = AT_STATE_HOOK;
  else
    vd_do_cmd();
}

function vd_at_state_hook()
{
  global $vd_at_state, $sn_tcp_ac_pid;
  
  if(tcp_state(0) != TCP_CLOSED)
  {
    $pid = $sn_tcp_ac_pid[0];
    if($pid)
      pid_close($pid);
    $sn_tcp_ac_pid[0] = 0;
  }
  
  vd_at_result(AT_MSG_NO_CARRIER);
  
  $vd_at_state = AT_STATE_CMD;
}
//------------------------------------------------

function vd_tcp2uart()
{
  global $vd_at_state, $vd_atc_uart_id;
  
  if($vd_at_state != AT_STATE_OL && $vd_at_state != AT_STATE_OL_CMD)
    return;
  
  if(tcp_state(0) == TCP_CONNECTED)
  {
    //----------------------------------------------------
    // TCP -> UART
    $txfree = uart_txfree($vd_atc_uart_id);
    if($txfree > 0)
    {
      $rbuf = "";
      if(tcp_read(0, $rbuf, $txfree) > 0)
      {
        uart_write($vd_atc_uart_id, $rbuf);
      }
    }
    //----------------------------------------------------
  }
}

function atc_setup($uart_id)
{
  global $vd_envs;
  global $vd_atc_uart_id;
  global $vd_local_port, $vd_peer_address, $vd_peer_port;
  
  $vd_atc_uart_id = $uart_id;
  
  $vd_envs = envs_read();
  
  $vd_local_port = 1470;
  $vd_peer_address = "";
  $vd_peer_port = 1470;
  
  //-----------------------------------------------
  // INITIALIZE
  vd_at_reset();
  //-----------------------------------------------
}

function atc_loop()
{
  global $vd_at_state;
  
  switch($vd_at_state)
  {
    case AT_STATE_CMD:
      vd_at_state_cmd();
      break;
    case AT_STATE_DIAL:
      vd_at_state_dial();
      break;
    case AT_STATE_OL:
      vd_at_state_ol();
      break;
    case AT_STATE_OL_CMD:
      vd_at_state_ol_cmd();
      break;
    case AT_STATE_HOOK:
      vd_at_state_hook();
      break;
  }
  vd_tcp2uart();
}

?>