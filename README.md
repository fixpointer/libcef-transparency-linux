# Transparency patch for Spotify

This is a library that patches Spotify and `libcef.so` in-memory to give the main X11 window a transparent background.

**Note: This does NOT make any visual changes to the Spotify application by itself. It is further required to apply changes to the CSS so that some parts of the web content are rendered transparent as well. This is not in scope for this project - you need something like a Spicetify theme with transparency to make use of this**

This is primarily intended to be used with the [WMPotify Theme](https://github.com/Ingan121/WMPotify) to fully replicate the Aero look on Linux (KDE Plasma w/ AeroThemePlasma).

## Installation instructions
1. Run `make` to build the library, this will generate `patcher_lib.so`
2. Run Spotify with the environment variable `LD_AUDIT=<full path to the library>`. For example, when Spotify is installed in its usual `/usr/share/spotify` directory, place the library there and run `LD_AUDIT=/usr/share/spotify/patcher_lib.so /usr/share/spotify/spotify`

The patch is only active if spotify is loaded with the library. To make it somewhat permanent, specify the environment variable in the `.desktop` file for spotify (most distros will come with an editor for this). This makes uninstallation easier - all that is necessary is to remove the environment variable, and the patch will not be applied anymore.
