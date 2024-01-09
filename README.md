# altherma-spoofer

A simple Java app that simulates a Daikin Heat Pump.
Its purpose is to play around with ESPAltherma and D-checker.

It works in two different ways, based on theconfig  parameter 'mqtt':

- standalone (mqtt = false):
  - read register data from file 'work/data.txt'
  - you can modify this file (**do not alter its structure!**) and the app will reload it on the fly
- mqtt (mqtt = true):
  - read register data subscribing to MQTT 'espaltherma/log'
  - you can modify the file 'work/spoof.txt' (**do not alter its structure!**) and the app will reload it on the fly
  - this file overwrites bytes received from MQTT where the file has a value != '--' (it's easier to do than to explain)

The app will calculate CRC on its own, so do not include CRC values in these files.
The first line of both files is a header and it is not parsed, so don't modify it.

## how to use ##
 - import this repo inside your IDE (I use eclipse)
 - create the config file 'src/main/resources/config.properties' (copy 'config.default.properties')
 - set the parameters with your values
 - build and launch (no command-line args required/supported)
 - eventually give firewall permission for inbound port 50000
 - wait for data, if using mqtt mode
 - launch D-checker
 - configure options (only the first time)
   - click 'Options'
   - select 'COM port' = 'TCP/IP(WiFi)'
   - set address to '127.0.0.1'
   - fill 'Service office' field with whatever
   - fill 'Responsible person' field with whatever
   - click 'OK'
 - click 'Recording'
 - add a customer (only the first time)
   - click 'Add new'
   - fill 'Customer id' field with whatever
   - fill 'Customer name' field with whatever
   - click 'Ok'
 - double click the customer row you want to use
 - click 'New'
 - ensure the checkbox 'With BTSC/Wi-Fi' is **not** ticked
 - click 'Altherma'
 - wait for detection to end
 - select an option for the field 'Data label file'
 - click 'Ok'
 - select the tab 'Op. All data'
 - now, you should see 6 tables of key-value pairs

At this point, you can modify the data/spoof file and you should see the changes reflected into D-checker GUI.

