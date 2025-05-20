# app_rtsp_sip
app_rtsp_sip.c is an [Asterisk](https://www.asterisk.org/) application tailored for connecting the audio streams of a Vivotek based IP camera to an Asterisk Channel.  The code was originally `app_rtsp.c` developed by Sergio Garcia Murillo. `app_rtsp.c` acted as an RTSP client/player which could setup an RTSP connection to an endpoint implementing an RTSP Server (such as that embedded inside a camera) and play the audio and video streams from the RTSP Server into a "calling" Asterisk channel.  In this manner, `app_rtsp` itself acted as an endpoint of an Asterisk Channel.

`app_rtsp_sip` has updated the `app_rtsp` code to compile and run on Asterisk 17.x, PLUS it has added a simple SIP UA capability for setting up a SIP Session and subsequenlty sending RTP audio from the same Asterisk channel to the same camera.  In effect, an Asterisk calling entity can establish two-way audio with a surveillance camera. If only RTSP is needed, the `app_rtsp_sip` application can be setup in Asterisk to only use RTSP.

In-line documentation was added to app_rtsp_sip.c so that one can view its documentation at the Asterisk command line.

## Restrictions/Limits/Quirks
- `app_rtsp_sip` has been developed and tested on a couple of Vivotek Cameras, as well as a Vivint Video Doorbell running Vivotek software that was configured for local use with Home Assistant.  It is possible that `app_rtsp_sip` may work with other cameras/devices but it is left up to the user of this software to determine how best to work with this code for such devices.
- Digest authentication uses hashing code that may not work on certain cpu architectures possibly those running Big Endian (but not tested).

The RTSP portion of the code originially developed by Sergiao Garcia Murillo and that has been ported to Asterisk has not been tested for the following:
- RTSP Video
- IPv6
- RTSP Tunnel
- Use DTMF to stop RTSP
- RTSP Digest Authentication (code is incomplete). *Digest Authentication has been added for SIP as Vivotek uses Digest Authentication for SIP.  Vivotek by default uses Basic Authentication for RTSP which is what the original code supported.*

# Asterisk

## Building Asterisk
*I'll share the following as a guide based on my experience installing Asterisk on various versions of Ubuntu.  It is not meant to be a "goto" all knowing guide necessarily as there may be missing dependencies or other asterisk build configuration options needed. Here is another handy [reference](https://websiteforstudents.com/how-to-install-asterisk-on-ubuntu-18-04-16-04/) you can also refer to.  If you're wondering about FreePBX, I don't have any experience trying to incorporate a new application into it so I can't offer any guidance for it.*

_The following assumes the build was done in a home directory: ~/asterisk/.  You can of course do this somewhere else such as /usr/src/_
```
$ sudo apt install wget build-essential subversion
$ cd ~/asterisk
$ sudo wget http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-17-current.tar.gz
$ sudo tar zxf asterisk-17-current.tar.gz
$ cd ~/asterisk/asterisk-17.<sub-version>
$ sudo contrib/scripts/install_prereq install
```
Where `<sub-version>` will be the current dot release of Asterisk 17. For example in Asterisk release 17.5, `5` is the `<sub-version>`.
This last step will prompt you for a country code.  Its not needed AFAIK and you can go with the default, or you can use your country's code (Ex. U.S is '1').  When completed, you should see `install completed successfully`.

Next run the build config.  
```
$ sudo ./configure
```
When finished you should see `configure: Menuselect build configuration successfully completed`

Next,
```
$ sudo make menuselect
```
You should see a menu pop up with an option set of applications, options, etc. you can add/remove. No real neeed to change anything.  *This does not incorporate app_rtsp_sip into the choice of applications so you won't see it in the choice of applications to install*.

Next, determine how many cores your machine has (it will be needed in a subsequent step).  In this example the number is 2:
```
$ cat /proc/cpuinfo | grep cores
CPU cores	: 2
```
Now compile the Asterisk code where '2' refers to the number of CPU cores (use the appropriate number for your system):
```
$ sudo make -j2 
``` 
*Go get a cup of coffee!*
When complete, it should show:
```
 +--------- Asterisk Build Complete ---------+
 + Asterisk has successfully been built, and +
 + can be installed by running:              +
 +                                           +
 +                make install               +
 +-------------------------------------------+
```  
Do NOT do the `make install` yet.

## Integrating app_rtsp_sip into the build
Assuming all went well with the Build, you can now copy the `app_rtsp_sip.c` file into the `../asterisk-17-<subversion>/apps/` directory with all the other app_xxx files.

- *For the Original version of app_rtsp_sip and Asterisk versions 17.x and 18.x* - If you are using the original version of app_rtsp_sip, you need to first run the `rtsp_sip_links.sh` before compiling.  The reason for the shell script is that app_rtsp_sip adds digest authentication and instead of re-inventing the wheel, it uses the digest authentication from the PJSIP project.  This requires the use of several pjproject include files which are scattered about under the pjproject directory and not available in the make files to application files.  This shell script simply adds symbolic links in the regular Asterisk include directory to all the needed pjsip/includes.
 Copy the `rtsp_sip_links.sh` file into the `~/asterisk/asterisk.<subversion>/` directory, then run it: `$ sudo ./rtsp_sip_links.sh`.  app_rtsp_sip version 1.1 now incorporates its own digest authentication and the script is not used.

We can now compile app_rtsp_sip and create the necessary shared libraries used by Asterisk.
Redo the make like we did before (2 in this example is the number of CPU cores):
```
$ sudo make -j2
```
If successful you can now install it.
## Installing Asterisk and app_rtsp_sip
From the same directory we did the build, run:
```
$ sudo make install
```
If successful, you'll see a text box indicating `Asterisk Installation Complete`. The `make install` should have picked up the app_rtsp_sip.so file and installed it with along with all the other app_xxx.so files. In Ubuntu, these are located at `/usr/lib/asterisk/modules/`

The text box also provides options to install other things (which I did):
```
$sudo make samples
$sudo make basic-pbx
```
Finish out by running:
```
$sudo make config
$sudo ldconfig

```
At this point, Asterisk is ready to run, however `app_rtsp_sip` will not automatically be loaded when asterisk is run. To have it loaded automatically, add a line to the `module.conf`: 
```
load = app_rtsp_sip.so
```
In Ubuntu, this file, along with all the other asterisk operational configuration files, is located in `/etc/asterisk/`.
If you want to load it manualy, you can do so by going into the Asterisk CLI and entering `module load app_rtsp_sip`.
## Running Asterisk
If you want to do a quick test to make sure things are working properly, enter: `$sudo asterisk` which will start Asterisk running, and then `$sudo asterisk -rvvvv` which will put you into the Asterisk CLI with the general debug level set to 4 (four `v`'s).

Using Ubuntu, the other way is to use `systemd` to `start/stop` Asterisk at any time, and `enable/disable` to restart/not-restart Asterisk over reboots.  Asterisk places the necessary information in `/etc/init.d/` scripts, and systemd will scan these files and create internal "service units", so you don't have to create systemd service unit files yourself.  You can use the following shell commands:
```
$sudo systemctl start asterisk
$sudo systemctl restart asterisk
$sudo systemctl stop asterisk
$sudo systemctl enable asterisk
$sudo systemctl disable asterisk
```

# Vivint Video Doorbell/Vivotek Cameras and Asterisk Setup
Vivint provides certain Video Doorbells, such as the V-DBC2S (VS-DBC250-110, VS-DBC251-110), that use Vivotek software to manage the video and audio aspects of the doorbell.  This section provides guidelines that can be used to setup a Vivint Doorbell/Vivotek Camera and Asterisk for two-way audio communications for use with app_rtsp_sip. *This is a [good reference point](https://community.home-assistant.io/t/vivint-doorbell-integration/145194) if one is more intested in the Vivint Doorbell particularly for use with Home Assistant.*

## Vivint/Vivotek
The guidelines in this section are mainly interested in configuring a new voice user into the Vivint/Vivotek device and the easiest way is to use the devices Web GUI. Vivotek has a webserver that allows a webbrowser to be used to access the camera's settings and configuration.  Historially, Vivotek used Internet Explorer along with downloadable plugins to manage most aspects of the device.  Using other web browsers may work as well with certain limitations, but for configuring a new voice user, these plug-ins should not be required.    

### Enable the Web Server
For Vivint video doorbell cameras, its webserver is initially restricted where it does not provide full web access.  You can give it a quick try by going to `http://IP_ADDRESS//cgi-bin/admin/getparam.cgi` (where IP_ADDRESS is the ip address of the camera).  You will be prompted for a username/password which by default is `root/adcvideo`.  This should return a large set of parameter settings.  If the parameter `network_http_webaccess` is set to zero, then set it to 1, which will enable full access to the webserver, by going to the following: `http://IP_ADDRESS//cgi-bin/admin/setparam.cgi?network_http_webaccess=1` which should return with this setting.  If successful, then full access to the webserver should now work.
  
### Enable SIP
Another parameter of interest is `capability_protocol_sip`, which is possibly set to 0.  If it is 0, then change it 1 using `http://<IPADDR>//cgi-bin/admin/setparam.cgi?capability_protocol_sip=1`.  Note: Although this will enable SIP, the camera will NOT provide SIP registration (as it does not know where/how to reach the SIP server), but this should not be necessary.

### Configure SIP User
Using the web browser, navigate to the "Account Manager" page (example navagation path: ->Security->User accounts->Account management). Then "Add new user" and provide username DOORBELL_PHONE_EXTENSION and password DOORBELL_USER_PASSWORD and set the privilege level to "Operator".  DOORBELL_PHONE_EXTENSION is the phone number such as "2001" that Asterisk will use to call the camera, and DOORBELL_USER_PASSWORD (you provide your own password here) is used for further authentication.  Note: app_rtsp_sip will also use this newly created user for RTSP.

## Configuring Asterisk
PJSIP (the newer SIP protocol engine) in Asterisk will be used in these guidelines.  If you already know how to setup a "calling" endpoint, all that this needed is to setup an extension that calls the app_rtsp_sip application.  A phantom phone number is used, which means a number that is not configured into Asterisk as an endpoint. Here is an example where the video camera is called by your calling endpoint to a phantom extension number `101` using the `from-internal` context:

**extensions.conf**
```
[from-internal]
;Doorbell 2-way
exten = 101,1,Answer()
same = n,Wait(1)
same = n,RTSP-SIP(rtsp://DOORBELL_PHONE_EXTENSION:DOORBELL_USER_PASSWORD@IP_ADDRESS:554/live.sdp,1,streaming_server,5060)
same = n,Wait(5)
same = n,Hangup()
```
When you call extension 101, Asterisk will use the context `from-internal` to Answer the calling endpoint, wait 1 sec, and execute the app_rtsp_sip application, where:
- `DOORBELL_PHONE_EXTENSION` is the RTSP/SIP username
- `DOORBELL_USER_PASSWORD` is the RTSP/SIP password.
- `IP_ADDRESS` is the address of the camera
- `554` is the RTSP port number, which is the default.
- `live.sdp` is the portion of the URL that is used by the camera for establishing RTSP to a particular stream on the camera.  This is the default for Vivotek cameras.
- `1` indicates that SIP is to be used.  If you only want to use RTSP and not both RTSP and SIP, then set this to 0.
- `streaming_server` is the realm used for digest authentication.  This is the default for Vivotek cameras.
- `5060` is the SIP port number, which is the default.

The app_rtsp_sip application is not expected to hangup by itself, but instead will wait for the calling party to hangup.


If you don't have a calling endpoint setup, here is an example using [ZoIPer](https://www.zoiper.com/softphone) softphone SIP client (which you can run on windows, iOS, etc) where here it is setup with phone extension number 6001.

**pjsip.conf**
```
[transport-udp-nat]
type = transport
protocol = udp
bind = 0.0.0.0:5060
allow_reload=no
; NAT settings
local_net=YOUR_IP_SUBNET/MASK

; ZoIPer iPhone
[6001]
type=endpoint
context=from-internal
disallow=all
allow=ulaw
auth=6001
aors=6001
transport=transport-udp-nat

[6001]
type=auth
auth_type=userpass
password=YOUR_PASSWORD
username=6001

[6001]
type=aor
max_contacts=1
```

Or if you want to use a WebRTC based SIP Client as a calling endpoint, refer to the [DoorVivint Card](https://github.com/tommyjlong/doorvivint-card) writeup on WebRTC.


If you want to place a 1-way SIP call to the camera, then add the following to the above files, assuming the camera username DOORBELL_EXTENSION is 2001.  Note: this also sets up static SIP registration since the camera is not dynamically registering for SIP services to the Asterisk SIP Server.

**pjsip.conf**
```
;Doorbell 1-way
[2001]
type=endpoint
context=from-internal
aors=2001
auth=2001
transport=transport-udp-nat
allow=ulaw,alaw,gsm,g726,g722
direct_media=no
outbound_auth = 2001

[2001]
type=auth
auth_type=userpass
password=DOORBELL_PASSWORD
username=2001
realm = streaming_server

[2001]
type=aor
max_contacts=1
remove_existing=yes
maximum_expiration=7200
minimum_expiration=60
qualify_frequency=60
contact = sip:2001@IP_ADDRESS:5060
```

**extensions.conf**
```
exten = 2001,1,Dial(PJSIP/2001)
```
# Home Assistant Asterisk AddOn
Home Assistant has a community AddOn that runs Asterisk and integrates well into the Home Assistant OS environment running as a Docker container.
The app_rtsp_sip code has also been incorported into AddOn's build and has been used with other cameras. Information on the AddOn can be found here - [HA Asterisk AddOn](https://github.com/TECH7Fox/asterisk-hass-addons). 

# History
- version 1.1
  - Updates to run on Asterisk 22.2.  Around Asterisk version 20.12.0, the pjsip routine that was used for Digest Authentication response stopped working.  This update uses its own Digest Authentication.
  - There is a bug when using certain cameras that provide both a Digest and a Basic Authentication header for RTSP and the Basic Authentication is in the second header (second header is not supported).  A work-around compile option is made available to always do a Basic Authentication.  This particularly for use with the Home Assistant Asterisk AddOn.
- version 1.0 Ported the original app_rtsp.c code to Asterisk version 17.x and add a SIP client to call the camera for setting up a audio channel to the camera.
# Credits
- Sergio Garcia Murillo, the author of the original app_rtsp.c code.

