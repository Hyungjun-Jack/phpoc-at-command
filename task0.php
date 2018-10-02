<?php
include_once "vd_atc.php";

$uart_id = 0;

uart_setup($uart_id, 115200, "N81N");

atc_setup($uart_id);

while(1)
{
  atc_loop();
}
?>