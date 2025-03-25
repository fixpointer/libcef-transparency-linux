# Transparency patch for Spotify

This is a library that patches Spotify and `libcef.so` in-memory to give the main X11 window a transparent background.

**Note: This does NOT make any visual changes to the Spotify application by itself. It is further required to apply changes to the CSS so that some parts of the web content are rendered transparent as well. This is not in scope for this project - you need something like a Spicetify theme with transparency to make use of this**

This is primarily intended to be used with the [WMPotify Theme](https://github.com/Ingan121/WMPotify) to fully replicate the Aero look on Linux (KDE Plasma w/ AeroThemePlasma).

WMPotify on Linux with patch:
![image](https://github.com/user-attachments/assets/e9e8e4f3-73db-468d-b457-f04c86630520)

WMPotify on Linux without patch:
![image](https://github.com/user-attachments/assets/263dc83d-75d4-433a-b4e9-8dda4c00cb80)



## Installation instructions
1. Run `make` to build the library, this will generate `patcher_lib.so`
2. Run Spotify with the environment variable `LD_AUDIT=<full path to the library>`. For example, when Spotify is installed in its usual `/usr/share/spotify` directory, place the library there and run `LD_AUDIT=/usr/share/spotify/patcher_lib.so /usr/share/spotify/spotify`

The patch is only active if spotify is loaded with the library. To make it somewhat permanent, specify the environment variable in the `.desktop` file for spotify (most distros will come with an editor for this). This makes uninstallation easier - all that is necessary is to remove the environment variable, and the patch will not be applied anymore.

For now, you will also need to adjust the settings in AeroThemePlasma to get proper blur behind the window:

- In the settings for the "Aero Glass Blur" desktop effect, add the "spotify" window class (without quotes) to the list of windows to force blur
- In the settings for the SMOD decoration, add an override for the "spotify" window class and disable drawing of inner borders

## Troubleshooting
When you run spotify from the command line, the patch will print diagnostic messages (prefixed with `[aero_patcher]`. When all goes well, you should only see the `[aero_patcher] have successfully patched libcef` message appear (possibly multiple times, because the app will create multiple subprocesses). 
Otherwise, there will be an error message describing what went wrong in the patching process. In this case, please create an issue with the log messages attached. If you get no message at all, the environment variable may not be set correctly.
