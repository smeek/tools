#!/bin/bash
DT=`date --utc --iso-8601=seconds`
#echo "Date/Time: $DT"
TEMP_C=`temper-poll --celsius`
RHUM_PC=`temper-poll --humidity`
#echo "Temperature: $TEMP_C°C"
#echo "Humidity: $RHUM_PC%RH"
EXT_TEMP_RHUM=`darksky ~/bin/darksky.config`
#echo "Ext. Temperature & Humidity: $EXT_TEMP_RHUM"
echo "$DT,$TEMP_C,$RHUM_PC,$EXT_TEMP_RHUM"
